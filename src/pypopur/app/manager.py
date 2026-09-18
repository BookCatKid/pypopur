"""Port of ``UnifiedDeviceControlManager`` — device state + dynamic dispatch.

The app wraps SDK device instances (``ThingHomeSdk.newDeviceInstance``) and
probes their methods reflectively.  In Python the same probing is done with
``getattr``/``inspect`` against the device object's methods.

Field-name map (obfuscated smali -> port):

- ``b`` -> ``device_instances``
- ``c`` -> ``listener_bridges``
- ``d`` -> ``app_listeners``
- ``e`` -> ``_states`` (the MutableStateFlow value)
- ``g`` -> ``full_listener_flags``
"""

from __future__ import annotations

import inspect
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from .dp_string import (
    dp_flag_arg,
    dp_string_arg,
    parse_dp_string,
    parse_org_json_object,
    serialize_dps,
)

_LOG = logging.getLogger("pypopur.app.manager")

DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
NO_CONTROL_METHOD = "NO_CONTROL_METHOD"
COMMAND_EXCEPTION = "COMMAND_EXCEPTION"
BATCH_QUERY_EXCEPTION = "BATCH_QUERY_EXCEPTION"
SDK_ERROR = "SDK_ERROR"

_FULL_LISTENER_INTERFACES = (
    "com.thingclips.smart.home.sdk.callback.IDevListener",
    "com.thingclips.smart.sdk.callback.IDevListener",
    "com.thingclips.smart.home.sdk.api.IDevListener",
    "com.thingclips.smart.sdk.api.IDevListener",
    "com.thingclips.smart.sdk.api.IDeviceListener",
    "com.tuya.smart.sdk.api.IDevListener",
    "com.tuya.smart.sdk.api.IDeviceListener",
)
_REGISTER_METHOD_NAMES = ("registerDevListener", "registerDeviceListener")
_RAW_NAME_TOKENS = ("raw", "command", "hex")


class DeviceControlCallback(Protocol):
    """``UnifiedDeviceControlManager$DeviceControlCallback``."""

    def on_error(self, code: str, error: str) -> None: ...

    def on_success(self) -> None: ...


class DeviceListener(Protocol):
    """``UnifiedDeviceControlManager$DeviceListener``."""

    def on_dev_info_update(self, device_id: str) -> None: ...

    def on_dp_update(self, device_id: str, dp_str: str) -> None: ...

    def on_network_status_changed(self, device_id: str, online: bool) -> None: ...

    def on_removed(self, device_id: str) -> None: ...

    def on_status_changed(self, device_id: str, online: bool) -> None: ...


_KEEP = object()


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclass(frozen=True, slots=True)
class DeviceState:
    """``UnifiedDeviceControlManager$DeviceState``.

    ``e``/``f``/``g`` keep the obfuscated field names: ``onNetworkStatusChanged``
    writes ``e``, ``onStatusChanged`` writes ``online``, and ``f`` is never
    replaced by any ``copy`` call site.
    """

    device_id: str
    online: bool = False
    dp_data: Mapping[str, Any] = field(default_factory=dict)
    timestamp: int = field(default_factory=_now_ms)
    e: bool = True
    f: bool = False
    g: bool = False

    def copy(
        self,
        online: Any = _KEEP,
        dp_data: Any = _KEEP,
        timestamp: Any = _KEEP,
        e: Any = _KEEP,
        g: Any = _KEEP,
    ) -> DeviceState:
        """Kotlin ``copy`` — ``f`` is not a copy parameter and always keeps."""

        return DeviceState(
            self.device_id,
            self.online if online is _KEEP else online,
            self.dp_data if dp_data is _KEEP else dp_data,
            self.timestamp if timestamp is _KEEP else timestamp,
            self.e if e is _KEEP else e,
            self.f,
            self.g if g is _KEEP else g,
        )


def _param_count(fn: Callable) -> int | None:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return None
    return len(
        [
            p
            for p in sig.parameters.values()
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
        ]
    )


def _first_param_annotation(fn: Callable) -> Any:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return None
    for p in sig.parameters.values():
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY):
            return p.annotation if p.annotation is not p.empty else None
    return None


def _annotation_is_map(annotation: Any) -> bool:
    if annotation is None:
        return False
    if annotation in (dict, Mapping):
        return True
    name = getattr(annotation, "__qualname__", None) or getattr(annotation, "__name__", "")
    if isinstance(annotation, str):
        name = annotation
    return "Map" in name


def _annotation_is_string(annotation: Any) -> bool:
    if annotation is None:
        return False
    if annotation is str:
        return True
    name = getattr(annotation, "__qualname__", None) or getattr(annotation, "__name__", "")
    if isinstance(annotation, str):
        name = annotation
    return name in ("str", "String")


def _annotation_is_json_object(annotation: Any) -> bool:
    if annotation is None:
        return False
    name = getattr(annotation, "__qualname__", None) or getattr(annotation, "__name__", "")
    if isinstance(annotation, str):
        name = annotation
    return "JSONObject" in name or "JSONObject" in str(annotation)


def _annotation_accepts_string(annotation: Any) -> bool:
    return annotation is None or _annotation_is_string(annotation)


def _public_callables(obj: Any) -> list[tuple[str, Callable]]:
    out = []
    for name in dir(obj):
        if name.startswith("_"):
            continue
        try:
            attr = getattr(obj, name)
        except Exception:
            continue
        if callable(attr):
            out.append((name, attr))
    return out


class _ResultProxy:
    """``p0`` — the ``e(cb)`` IResultCallback proxy: errors collapse to SDK_ERROR."""

    def __init__(self, callback: DeviceControlCallback):
        self._callback = callback

    def on_error(self, code: str, error: str) -> None:
        self._callback.on_error(SDK_ERROR, "SDK方法调用失败")

    def on_success(self) -> None:
        self._callback.on_success()

    onError = on_error
    onSuccess = on_success


class _PublishResultProxy:
    """``q0`` mode-1 — ``publishDps(String, IResultCallback)`` proxy passthrough."""

    def __init__(self, callback: DeviceControlCallback):
        self._callback = callback

    def on_error(self, code: str, error: str) -> None:
        self._callback.on_error(code, error)

    def on_success(self) -> None:
        self._callback.on_success()

    onError = on_error
    onSuccess = on_success


class _SimpleDeviceListener:
    """``createSimpleDeviceListener$1`` — an intentionally empty object."""


class DeviceListenerBridge:
    """``createMulticastBridge$1`` — fans SDK events out to app listeners."""

    def __init__(self, manager: UnifiedDeviceControlManager, dev_id: str):
        self._manager = manager
        self._dev_id = dev_id

    def on_dev_info_update(self, device_id: str) -> None:
        self._manager._notify(self._dev_id, lambda l: l.on_dev_info_update(device_id))

    def on_dp_update(self, device_id: str, dp_str: str) -> None:
        self._manager._notify(self._dev_id, lambda l: l.on_dp_update(device_id, dp_str))

    def on_network_status_changed(self, device_id: str, online: bool) -> None:
        self._manager._notify(
            self._dev_id, lambda l: l.on_network_status_changed(device_id, online)
        )

    def on_removed(self, device_id: str) -> None:
        self._manager._notify(self._dev_id, lambda l: l.on_removed(device_id))

    def on_status_changed(self, device_id: str, online: bool) -> None:
        self._manager._notify(self._dev_id, lambda l: l.on_status_changed(device_id, online))


class _SdkListenerProxy:
    """``q0`` mode-0 — routes every SDK listener method into ``dispatch_callback``."""

    def __init__(self, manager: UnifiedDeviceControlManager, bridge: DeviceListenerBridge):
        self._manager = manager
        self._bridge = bridge

    def __getattr__(self, name: str) -> Callable:
        def _dispatch(*args: Any) -> None:
            try:
                self._manager.dispatch_callback(name, list(args), self._bridge)
            except Exception as exc:
                self._manager._record_exception(exc)

        return _dispatch


# Field order mirrors ``TuyaDeviceBeanDpsReader.a``: ``dps`` first, then the
# ``[dpData, deviceDps, allDps, dpMap, dataPoints]`` candidates (snake_case
# variants adjacent for Python beans). An empty map falls through.
_DP_FIELD_NAMES = (
    "dps",
    "dpData",
    "dp_data",
    "deviceDps",
    "device_dps",
    "allDps",
    "all_dps",
    "dpMap",
    "dp_map",
    "dataPoints",
    "data_points",
)


def read_device_dps(device: Any) -> dict[str, Any]:
    """``TuyaDeviceBeanDpsReader.a`` — getDps() then declared dp-map fields."""

    if device is None:
        return {}
    get_dps = getattr(device, "getDps", None) or getattr(device, "get_dps", None)
    if callable(get_dps):
        try:
            value = get_dps()
            if isinstance(value, Mapping) and value:
                return dict(value)
        except Exception:
            pass
    for name in _DP_FIELD_NAMES:
        try:
            value = getattr(device, name, None)
        except Exception:
            continue
        if isinstance(value, Mapping) and value:
            return dict(value)
    return {}


class UnifiedDeviceControlManager:
    """``UnifiedDeviceControlManager`` — device instances, state flow, listeners."""

    def __init__(
        self,
        crash_reporter: Callable[[BaseException], None] | None = None,
        device_factory: Callable[[str], Any] | None = None,
    ):
        self._record = crash_reporter or (lambda exc: _LOG.debug("crash: %r", exc))
        self._device_factory = device_factory or (lambda dev_id: None)
        self.device_instances: dict[str, Any] = {}
        self.listener_bridges: dict[str, Any] = {}
        # LinkedHashSet parity — dict keys keep insertion order for fan-out.
        self.app_listeners: dict[str, dict[DeviceListener, None]] = {}
        self.full_listener_flags: dict[str, bool] = {}
        self._states: dict[str, DeviceState] = {}

    def _record_exception(self, exc: BaseException) -> None:
        self._record(exc)

    @property
    def states(self) -> dict[str, DeviceState]:
        return dict(self._states)

    def device_state(self, dev_id: str) -> DeviceState | None:
        """``h``."""

        return self._states.get(dev_id)

    def _update_state(self, dev_id: str, state: DeviceState) -> None:
        """``v`` — copy-on-write publish into the state map."""

        merged = dict(self._states)
        merged[dev_id] = state
        self._states = merged

    def _default_state(self, dev_id: str, g: bool = False) -> DeviceState:
        """``DeviceState(mask=0x7e/0x3e, devId, g)`` — e=1, f=0, g=arg."""

        return DeviceState(dev_id, online=False, e=True, f=False, g=g)

    def get_or_create_device(self, dev_id: str) -> Any:
        """``j`` — ``ThingHomeSdk.newDeviceInstance`` with caching."""

        try:
            instance = self.device_instances.get(dev_id)
            if instance is not None:
                return instance
            instance = self._device_factory(dev_id)
            if instance is None:
                return None
            self.device_instances[dev_id] = instance
            # ctor mask 0x5e: f (isInitialized) defaults to true here.
            self._update_state(dev_id, DeviceState(dev_id, online=False, e=True, f=True, g=False))
            return instance
        except Exception as exc:
            self._record_exception(exc)
            return None

    def batch_query_dps(self, dev_id: str, callback: DeviceControlCallback) -> None:
        """``k`` — ensure the instance, then onSuccess (refresh rides listeners)."""

        try:
            instance = self.device_instances.get(dev_id)
            if instance is None:
                instance = self.get_or_create_device(dev_id)
                if instance is None:
                    callback.on_error(DEVICE_NOT_FOUND, "设备实例初始化失败")
                    return
            callback.on_success()
        except Exception as exc:
            callback.on_error(BATCH_QUERY_EXCEPTION, f"批量查询异常: {exc}")

    def register_listener(self, dev_id: str, listener: DeviceListener) -> bool:
        """``l`` — app listener add + SDK listener registration cascade."""

        try:
            instance = self.device_instances.get(dev_id)
            if instance is None:
                instance = self.get_or_create_device(dev_id)
            if instance is None:
                return False
            listeners = self.app_listeners.get(dev_id)
            if listeners is None:
                listeners = {}
                self.app_listeners[dev_id] = listeners
            if listener in listeners:
                return True
            listeners[listener] = None
            if dev_id in self.listener_bridges:
                return True
            bridge = DeviceListenerBridge(self, dev_id)
            if self._register_full_listener(dev_id, instance, bridge):
                self.full_listener_flags[dev_id] = True
                state = self.device_state(dev_id)
                self._update_state(
                    dev_id,
                    state.copy(g=True) if state is not None else self._default_state(dev_id, True),
                )
                return True
            if self._register_simple_listener(dev_id, instance, bridge):
                self.full_listener_flags[dev_id] = False
                state = self.device_state(dev_id)
                self._update_state(
                    dev_id,
                    state.copy(g=False)
                    if state is not None
                    else self._default_state(dev_id, False),
                )
                return True
            # 跳过监听器注册，仅保留控制功能 — still reports success.
            listeners.pop(listener, None)
            if not listeners:
                self.app_listeners.pop(dev_id, None)
            self.full_listener_flags[dev_id] = False
            return True
        except Exception as exc:
            self._record_exception(exc)
            return False

    def _register_full_listener(
        self, dev_id: str, instance: Any, bridge: DeviceListenerBridge
    ) -> bool:
        """``r`` — proxy + ``registerDevListener``/``registerDeviceListener``."""

        try:
            proxy = _SdkListenerProxy(self, bridge)
            for name in _REGISTER_METHOD_NAMES:
                for snake in (name, _snake(name)):
                    method = getattr(instance, snake, None)
                    if callable(method):
                        method(proxy)
                        self.listener_bridges[dev_id] = proxy
                        return True
            return False
        except Exception as exc:
            self._record_exception(exc)
            return False

    def _register_simple_listener(
        self, dev_id: str, instance: Any, bridge: DeviceListenerBridge
    ) -> bool:
        """``s`` — any ``registerDevListener`` gets an empty listener object."""

        try:
            for name, method in _public_callables(instance):
                if name == "registerDevListener" or name == "register_dev_listener":
                    listener = _SimpleDeviceListener()
                    method(listener)
                    self.listener_bridges[dev_id] = listener
                    return True
            return False
        except Exception as exc:
            self._record_exception(exc)
            return False

    def unregister_listener(self, dev_id: str, listener: DeviceListener) -> bool:
        """``t``."""

        try:
            listeners = self.app_listeners.get(dev_id)
            if listeners is None or listener not in listeners:
                return False
            del listeners[listener]
            if not listeners:
                self.app_listeners.pop(dev_id, None)
                self.unregister_sdk_listener(dev_id)
            return True
        except Exception as exc:
            self._record_exception(exc)
            return False

    def unregister_sdk_listener(self, dev_id: str) -> bool:
        """``u``."""

        try:
            instance = self.device_instances.get(dev_id)
            if instance is None:
                self.listener_bridges.pop(dev_id, None)
                self.full_listener_flags.pop(dev_id, None)
                return False
            try:
                unregister = getattr(instance, "unRegisterDevListener", None) or getattr(
                    instance, "un_register_dev_listener", None
                )
                if callable(unregister):
                    unregister()
            except Exception:
                pass
            self.listener_bridges.pop(dev_id, None)
            self.full_listener_flags.pop(dev_id, None)
            return True
        except Exception as exc:
            self._record_exception(exc)
            return False

    def _notify(self, dev_id: str, fn: Callable[[DeviceListener], None]) -> None:
        """``a`` — snapshot the app listeners, isolate per-listener failures."""

        listeners = self.app_listeners.get(dev_id)
        for listener in list(listeners or ()):
            try:
                fn(listener)
            except Exception as exc:
                self._record_exception(exc)

    def dispatch_callback(
        self, method_name: str, args: list[Any] | None, bridge: DeviceListenerBridge
    ) -> None:
        """``i`` — the multicast InvocationHandler body."""

        if method_name == "onDevInfoUpdate" or method_name == "on_dev_info_update":
            dev_id = dp_string_arg(args)
            if dev_id is None:
                return
            bridge.on_dev_info_update(dev_id)
        elif method_name == "onNetworkStatusChanged" or method_name == (
            "on_network_status_changed"
        ):
            dev_id = dp_string_arg(args)
            if dev_id is None:
                return
            online = dp_flag_arg(args)
            state = self._states.get(dev_id) or self._default_state(dev_id)
            self._update_state(dev_id, state.copy(timestamp=_now_ms(), e=online))
            bridge.on_network_status_changed(dev_id, online)
        elif method_name == "onDpUpdate" or method_name == "on_dp_update":
            dev_id = dp_string_arg(args)
            if dev_id is None:
                return
            data = args[1] if args and len(args) > 1 else None
            if isinstance(data, str):
                dp_str = data
            elif isinstance(data, Mapping):
                dp_str = serialize_dps(dict(data))
            else:
                dp_str = str(data) if data is not None else "{}"
            try:
                parsed = parse_org_json_object(dp_str)
            except Exception:
                parsed = parse_dp_string(dp_str)
            state = self._states.get(dev_id) or self._default_state(dev_id)
            merged = dict(state.dp_data)
            merged.update(parsed)
            self._update_state(dev_id, state.copy(dp_data=merged, timestamp=_now_ms()))
            bridge.on_dp_update(dev_id, dp_str)
        elif method_name == "onStatusChanged" or method_name == "on_status_changed":
            dev_id = dp_string_arg(args)
            if dev_id is None:
                return
            online = dp_flag_arg(args)
            state = self._states.get(dev_id) or self._default_state(dev_id)
            self._update_state(dev_id, state.copy(online=online, timestamp=_now_ms()))
            bridge.on_status_changed(dev_id, online)
        elif method_name == "onRemoved" or method_name == "on_removed":
            dev_id = dp_string_arg(args)
            if dev_id is None:
                return
            self.app_listeners.pop(dev_id, None)
            self.unregister_sdk_listener(dev_id)
            self.device_instances.pop(dev_id, None)
            states = dict(self._states)
            states.pop(dev_id, None)
            self._states = states
            bridge.on_removed(dev_id)

    def query_device_dp(self, device: Any, callback: DeviceControlCallback) -> bool:
        """``n`` — read the bean's dp map and merge into state, marking online."""

        dps = read_device_dps(device)
        if not dps:
            return False
        # The ``b``-map fallback only runs when the getDevId lookup throws —
        # a non-String result goes straight to "unknown".
        dev_id = None
        get_dev_id = getattr(device, "get_dev_id", None) or getattr(device, "getDevId", None)
        try:
            if not callable(get_dev_id):
                raise AttributeError("getDevId")  # noqa: TRY004
            value = get_dev_id()
            if isinstance(value, str):
                dev_id = value
        except Exception:
            for key, instance in self.device_instances.items():
                if instance is device:
                    dev_id = key
                    break
        if dev_id is None:
            dev_id = "unknown"
        state = self._states.get(dev_id) or self._default_state(dev_id)
        merged = dict(state.dp_data)
        merged.update(dps)
        self._update_state(
            dev_id,
            state.copy(online=True, dp_data=merged, timestamp=_now_ms()),
        )
        callback.on_success()
        return True

    def send_device_command(
        self, dev_id: str, dps: Mapping[str, Any], callback: DeviceControlCallback
    ) -> None:
        """``sendDeviceCommand`` — the ``p/o/m/q`` reflective cascade."""

        try:
            instance = self.device_instances.get(dev_id)
            if instance is None:
                instance = self.get_or_create_device(dev_id)
                if instance is None:
                    callback.on_error(DEVICE_NOT_FOUND, "设备实例初始化失败")
                    return
            has_bytes = any(isinstance(v, (bytes, bytearray, memoryview)) for v in dps.values())
            if has_bytes:
                ok = (
                    self._try_raw_passthrough(instance, dps, callback)
                    or self._try_simple_publish(instance, dps, callback)
                    or self._try_sdk_publish(instance, dps, callback)
                    or self._try_generic_publish(instance, dps, callback)
                )
            else:
                ok = (
                    self._try_sdk_publish(instance, dps, callback)
                    or self._try_simple_publish(instance, dps, callback)
                    or self._try_generic_publish(instance, dps, callback)
                )
            if not ok:
                callback.on_error(NO_CONTROL_METHOD, "无法找到可用的控制方法")
        except Exception as exc:
            self._record_exception(exc)
            callback.on_error(COMMAND_EXCEPTION, f"控制指令异常: {exc}")

    def _try_sdk_publish(
        self, instance: Any, dps: Mapping[str, Any], callback: DeviceControlCallback
    ) -> bool:
        """``p`` — ``publishDps(String, IResultCallback)``."""

        try:
            method = _find_publish_dps(instance)
            if method is None or _param_count(method) != 2:
                return False
            method(serialize_dps(dict(dps)), _PublishResultProxy(callback))
            return True
        except Exception:
            return False

    def _try_simple_publish(
        self, instance: Any, dps: Mapping[str, Any], callback: DeviceControlCallback
    ) -> bool:
        """``o`` — ``publishDps`` with String/Map/JSONObject parameter."""

        try:
            method = _find_publish_dps(instance)
            if method is None or _param_count(method) != 1:
                return False
            serialized = serialize_dps(dict(dps))
            annotation = _first_param_annotation(method)
            if _annotation_is_map(annotation):
                method(
                    {
                        k: _b64(v) if isinstance(v, (bytes, bytearray, memoryview)) else v
                        for k, v in dps.items()
                    }
                )
            elif _annotation_is_json_object(annotation):
                method(parse_org_json_object(serialized))
            else:
                method(serialized)
            callback.on_success()
            return True
        except Exception:
            return False

    def _try_generic_publish(
        self, instance: Any, dps: Mapping[str, Any], callback: DeviceControlCallback
    ) -> bool:
        """``m`` — publish/send/control-named single-arg methods get the string."""

        try:
            for name, method in _public_callables(instance):
                lowered = name.lower()
                if not any(t in lowered for t in ("publish", "send", "control")):
                    continue
                if _param_count(method) != 1:
                    continue
                if not _annotation_accepts_string(_first_param_annotation(method)):
                    continue
                try:
                    method(serialize_dps(dict(dps)))
                    callback.on_success()
                    return True
                except Exception:
                    continue
            return False
        except Exception:
            return False

    def _try_raw_passthrough(
        self, instance: Any, dps: Mapping[str, Any], callback: DeviceControlCallback
    ) -> bool:
        """``q`` — raw/command/hex/publishcommands methods, 1–2 params."""

        try:
            first_entry = next(iter(dps.items()), None)
            for name, method in _public_callables(instance):
                lowered = name.lower()
                if not (
                    any(t in lowered for t in _RAW_NAME_TOKENS) or lowered == "publishcommands"
                ):
                    continue
                count = _param_count(method)
                if count not in (1, 2):
                    continue
                annotation = _first_param_annotation(method)
                try:
                    if count == 1:
                        if _annotation_is_map(annotation):
                            method(dps)
                            callback.on_success()
                            return True
                        if first_entry is not None and isinstance(
                            first_entry[1], (bytes, bytearray, memoryview)
                        ):
                            method(bytes(first_entry[1]))
                            callback.on_success()
                            return True
                    else:
                        if _annotation_is_map(annotation):
                            method(dps, _ResultProxy(callback))
                            return True
                        if first_entry is not None and isinstance(
                            first_entry[1], (bytes, bytearray, memoryview)
                        ):
                            method(first_entry[0], bytes(first_entry[1]))
                            callback.on_success()
                            return True
                except Exception:
                    continue
            return False
        except Exception:
            return False


def _snake(name: str) -> str:
    out = []
    for ch in name:
        if ch.isupper() and out:
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


def _find_publish_dps(instance: Any) -> Callable | None:
    for name in ("publishDps", "publish_dps"):
        method = getattr(instance, name, None)
        if callable(method):
            return method
    return None


def _b64(value: bytes | bytearray | memoryview) -> str:
    import base64

    return base64.b64encode(bytes(value)).decode()
