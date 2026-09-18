"""Low-power device wake manager — ``com.thingclips.sdk.device.bdqqqbp``
(``LowPowerDeviceManager``) ported opcode-faithful.

Flow (``bdpdqbp(devId, timeoutMs, IThingResultCallback)``):

1. ``callback == null`` → bare awake publish via ``pdqppqb(String)``.
2. ``devId`` empty → ``onError("1001", "Device model does not exist.")``.
3. ``resp`` missing → ``onError("1002", "Device response bean not found")``.
4. ``communicationNode`` non-empty and != devId → redirect to the node
   (missing → ``onSuccess(UNSUPPORT)``).
5. ``productRefBean`` missing → ``onError("1003", ...)``.
6. ``resp.isVirtual`` → ``onSuccess(SUCCESS)``.
7. ``productRef.configMetas`` lacking ``low_power_wakeup`` →
   ``onSuccess(UNSUPPORT)``.
8. ``timeoutMs > 0`` replaces the static default (10000 ms).
9. Fast path: recorded awake flag + ``cloudConnectLastUpdateTime >=
   recorded`` + cloud online → re-publish awake, ``onSuccess(SUCCESS)``.
10. Otherwise the callback joins ``pppbppp[devId]``; if a wake task is
    already running nothing more happens ("Wakeup task already
    exists."), else ``pdqppqb(resp)`` starts one.

The wake task (``$pppbppp`` runnable) re-publishes the MQTT awake frame
every 1000 ms while ``now - start < wakeTimeout``; on expiry it
dispatches ``AWAKE_TIMEOUT``.

Awake publish (``bdpdqbp(DeviceRespBean)``): MQTT
``publish("m/w/" + devId, intToByteArray(crc32(localKey)), qos=0,
retained=false)``.

Check-awake (``bdpdqbp(String)``): Business call
``m.thing.device.low.power.connect.batch.get`` v1.0 with
``devIds = JSON.stringify(list)``; on success, ``result[0]`` with
``lowPowerConnect == false`` marks the device awake
(``qpppdqb[devId]=true``, ``pbddddb[devId]=lastConnectChangeTime``) and
dispatches ``SUCCESS``; empty/null result dispatches ``UNSUPPORT``.

All platform plumbing — MQTT server, Business call, handler/scheduler —
is injected.
"""

from __future__ import annotations

import threading
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .device_cache import DeviceRespBean, DevListCacheManager


class LowPowerAwakeRsp:
    """``com.thingclips.smart.sdk.enums.LowPowerAwakeRsp`` — responseType."""

    UNSUPPORT = 1
    SUCCESS = 2
    AWAKE_TIMEOUT = 3


@dataclass
class LowPowerConnectResult:
    """``com.thingclips.sdk.device.bean.LowPowerConnectResult``."""

    last_connect_change_time: int = 0
    dev_id: str | None = None
    low_power_connect: bool = False


def _int_to_byte_array(value: int) -> bytes:
    """``qqpdpbp.bdpdqbp(int)`` — big-endian 4 bytes."""
    return bytes(((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _crc32(data: str | None) -> int:
    """``qqpdpbp.bdpdqbp(String)`` — table CRC32 (init -1, final ``not``),
    i.e. ``zlib.crc32`` of the raw ``String.getBytes()``."""
    return zlib.crc32(data.encode() if data is not None else b"")


class _Handler:
    """Android ``Handler`` seam — immediate post + delayed/cancel."""

    def __init__(
        self,
        post: Callable[[Callable[[], None]], None] | None = None,
        post_delayed: Callable[[Callable[[], None], int], None] | None = None,
        remove_callbacks: Callable[[Callable[[], None]], None] | None = None,
    ) -> None:
        self.post = post or (lambda fn: fn())
        self.post_delayed = post_delayed or (lambda fn, ms: fn())
        self.remove_callbacks = remove_callbacks or (lambda fn: None)


class TimerHandler(_Handler):
    """``Handler`` over ``threading.Timer`` — production ``post_delayed``.

    The default ``_Handler`` runs delayed posts immediately; for a real
    wake task that would busy-loop for the whole timeout. ``post`` still
    runs inline (the Java handler posts to the current thread's queue).
    """

    def __init__(self) -> None:
        self._timers: dict[Callable[[], None], threading.Timer] = {}
        super().__init__(self._post, self._post_delayed, self._remove)

    @staticmethod
    def _post(fn: Callable[[], None]) -> None:
        fn()

    def _post_delayed(self, fn: Callable[[], None], ms: int) -> None:
        timer = threading.Timer(ms / 1000, fn)
        timer.daemon = True
        self._timers[fn] = timer
        timer.start()

    def _remove(self, fn: Callable[[], None]) -> None:
        timer = self._timers.pop(fn, None)
        if timer is not None:
            timer.cancel()


class MqttServerAdapter:
    """``IMqttServer`` view over a ``MqttWireClient``-shaped client —
    reorders ``publish(topic, payload, cb, qos, retain)`` into the
    server's ``publish(topic, payload, qos, retained, cb)`` and forwards
    ``register_mqtt_callback``."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def publish(
        self,
        topic: str,
        payload: bytes,
        qos: int,
        retained: bool,
        cb: Any,
    ) -> None:
        self._client.publish(topic, payload, cb, qos, retained)

    def register_mqtt_callback(self, cb: Any) -> None:
        register = getattr(self._client, "register_mqtt_callback", None)
        if register is not None:
            register(cb)


class _MqttStatusCallback:
    """``bdqqqbp$pdqppqb`` — both connect events ``release(false)``."""

    def __init__(self, manager: LowPowerDeviceManager) -> None:
        self._manager = manager

    def on_connect_success(self) -> None:
        self._manager.release(False)

    def on_connect_error(self, code: str | None, error: str | None) -> None:
        self._manager.release(False)


def low_power_check_awake(business: Any) -> Callable[[list[str], Any], None]:
    """``qdddbpp.pdqppqb(List, ResultListener)`` — the
    ``m.thing.device.low.power.connect.batch.get`` v1.0 Business call
    (postData ``devIds`` = ``JSON.toJSONString(list)``, session required),
    adapted to the ``check_awake`` seam's sync ``Business.request``."""

    from ._fastjson import to_json_string

    def check_awake(dev_ids: list[str], listener: Any) -> None:
        params = business.new_api_params("m.thing.device.low.power.connect.batch.get", "1.0")
        params.put_post_data("devIds", to_json_string(dev_ids))
        params.session_require = True
        result = business.request(params)
        resp = result.response
        api_name = result.api_name
        if not result.succeeded:
            listener.on_failure(resp, result.data, api_name)
            return
        raw = resp.result if resp is not None else None
        results = [_connect_result(item) for item in raw] if isinstance(raw, list) else []
        listener.on_success(resp, results, api_name)

    return check_awake


def _connect_result(raw: Any) -> LowPowerConnectResult:
    """fastjson ``LowPowerConnectResult`` — camelCase bean fields."""
    raw = raw if isinstance(raw, dict) else {}
    return LowPowerConnectResult(
        last_connect_change_time=int(raw.get("lastConnectChangeTime") or 0),
        dev_id=raw.get("devId"),
        low_power_connect=bool(raw.get("lowPowerConnect")),
    )


class LowPowerDeviceManager:
    """``bdqqqbp`` singleton.

    Seams:

    - ``dev_cache`` — ``bpbqqdq``/``ppqqqpb`` (``get_dev_resp_bean``).
    - ``mqtt_server`` — ``IMqttServer``; needs
      ``publish(topic, payload, qos, retained, cb)``.
    - ``check_awake(dev_ids, listener)`` — the ``qdddbpp`` Business
      method (``m.thing.device.low.power.connect.batch.get`` v1.0);
      listener gets ``(biz_response, results, api_name)`` where
      ``results`` is ``List[LowPowerConnectResult]``.
    - ``handler`` — ``_Handler`` (post/post_delayed/remove_callbacks).
    - ``clock_ms`` — ``System.currentTimeMillis`` (wall clock).
    """

    DEFAULT_WAKE_TIMEOUT_MS = 10000  # pdqppqb = 0x2710
    WAKE_INTERVAL_MS = 1000  # $pppbppp repost delay

    def __init__(
        self,
        *,
        dev_cache: DevListCacheManager | None = None,
        mqtt_server: Any = None,
        check_awake: Callable[[list[str], Any], None] | None = None,
        handler: _Handler | None = None,
        clock_ms: Callable[[], int] = lambda: int(time.time() * 1000),
    ) -> None:
        self.dev_cache = dev_cache
        self.mqtt_server = mqtt_server
        self._check_awake = check_awake
        self.handler = handler or _Handler()
        self._clock_ms = clock_ms

        self.wake_timeout_ms = self.DEFAULT_WAKE_TIMEOUT_MS  # pdqppqb
        self.awake_flags: dict[str, bool] = {}  # qpppdqb
        self.awake_change_times: dict[str, int] = {}  # pbddddb
        self.wake_deadlines: dict[str, int] = {}  # pbpdpdp
        self.wake_tasks: dict[str, Callable[[], None]] = {}  # pbbppqb
        self.callbacks: dict[str, list[Any]] = {}  # pppbppp

        # ``pppbppp()`` — ``getMqttServerInstance().registerMqttCallback``;
        # the ``$pdqppqb`` status callback ``release(false)``s on both
        # connect success and error.
        register = getattr(mqtt_server, "register_mqtt_callback", None)
        if register is not None:
            register(_MqttStatusCallback(self))

    # --- entry: bdpdqbp(String, J, IThingResultCallback) -------------------

    def awake(self, dev_id: str | None, timeout_ms: int, callback: Any) -> None:
        if callback is None:
            # "callback is empty, just send awake command."
            self._awake_by_id(dev_id)
            return
        if dev_id is None or len(dev_id) == 0:
            callback.on_error("1001", "Device model does not exist.")
            return
        resp = self._get_resp(dev_id)
        if resp is None:
            callback.on_error("1002", "Device response bean not found")
            return
        node = None
        if resp.communication is not None:
            node = resp.communication.communication_node
        if node is not None and len(node) != 0 and node != dev_id:
            resp = self._get_resp(node)
            if resp is None:
                callback.on_success(LowPowerAwakeRsp.UNSUPPORT)
                return
            dev_id = node  # "awake dev X -change-> Y"
        product_ref = resp.product_ref_bean
        if product_ref is None:
            callback.on_error("1003", "Product reference bean not found")
            return
        if resp.virtual:
            callback.on_success(LowPowerAwakeRsp.SUCCESS)
            return
        metas = product_ref.config_metas
        if metas is None:
            metas = {}
        if "low_power_wakeup" not in metas:
            callback.on_success(LowPowerAwakeRsp.UNSUPPORT)
            return
        if timeout_ms > 0:
            self.wake_timeout_ms = timeout_ms
        flag = self.awake_flags.get(dev_id)
        stamp = self.awake_change_times.get(dev_id)
        if flag is not None and stamp is not None:
            cloud_online = resp.is_cloud_online()
            last_update = resp.device_biz_prop_bean.cloud_connect_last_update_time
            if flag and cloud_online and last_update >= stamp:
                # "The device has already been woken up."
                self.send_awake(resp)
                callback.on_success(LowPowerAwakeRsp.SUCCESS)
                return
        self._register_callback(dev_id, callback)
        if dev_id in self.wake_tasks:
            return  # "Wakeup task already exists."
        self._start_wake_task(resp)

    # --- callback registry -------------------------------------------------

    def _register_callback(self, dev_id: str, callback: Any) -> None:
        """``bdpdqbp(String, IThingResultCallback)`` — dedup'd append."""
        cbs = self.callbacks.get(dev_id)
        if cbs is not None:
            if callback not in cbs:
                cbs.append(callback)
            return
        self.callbacks[dev_id] = [callback]

    # --- result dispatch ----------------------------------------------------

    def dispatch_result(self, dev_id: str, rsp: int) -> None:
        """``bdpdqbp(String, LowPowerAwakeRsp)`` — cancel the wake task,
        drop the deadline, fan the result out to registered callbacks."""
        task = self.wake_tasks.pop(dev_id, None)
        if task is not None:
            self.handler.remove_callbacks(task)
        self.wake_deadlines.pop(dev_id, None)
        cbs = self.callbacks.get(dev_id)
        self.handler.post(lambda: self._fan_out(cbs, rsp))

    @staticmethod
    def _fan_out(cbs: list[Any] | None, rsp: int) -> None:
        """``bdpdqbp(List, LowPowerAwakeRsp)`` — ``onSuccess`` then remove
        each callback (the Java loop mutates during iteration over a
        CopyOnWriteArrayList)."""
        if cbs is None:
            return
        for cb in list(cbs):
            cb.on_success(rsp)
            cbs.remove(cb)

    # --- wake task -------------------------------------------------------------

    def _start_wake_task(self, resp: DeviceRespBean) -> None:
        """``pdqppqb(DeviceRespBean)`` — checkAwakeStatus, then loop the
        awake publish every 1 s until the deadline."""
        dev_id = resp.dev_id
        try:
            self.check_awake_status(dev_id)
            if dev_id not in self.wake_deadlines:
                self.wake_deadlines[dev_id] = self.wake_timeout_ms
            start = self._clock_ms()

            def _task() -> None:
                deadline = self.wake_deadlines.get(dev_id, 0)
                if self._clock_ms() - start < deadline:
                    self.handler.remove_callbacks(_task)
                    self.send_awake(resp)
                    self.handler.post_delayed(_task, self.WAKE_INTERVAL_MS)
                    return
                # "wake timeout"
                self.dispatch_result(dev_id, LowPowerAwakeRsp.AWAKE_TIMEOUT)

            self.handler.post(_task)
            self.wake_tasks[dev_id] = _task
        except Exception:
            # "The cloud check failed and the wake-up operation started
            # directly." → dispatch UNSUPPORT
            self.dispatch_result(dev_id, LowPowerAwakeRsp.UNSUPPORT)

    # --- awake publish -----------------------------------------------------------

    def send_awake(self, resp: DeviceRespBean) -> None:
        """``bdpdqbp(DeviceRespBean)`` — MQTT ``m/w/<devId>`` publish of
        the big-endian CRC32 of ``localKey`` (qos 0, not retained)."""
        local_key = resp.local_key
        dev_id = resp.dev_id
        topic = "m/w/" + dev_id
        payload = _int_to_byte_array(_crc32(local_key))
        server = self.mqtt_server
        if server is not None:
            server.publish(topic, payload, 0, False, None)

    def _awake_by_id(self, dev_id: str | None) -> None:
        """``pdqppqb(String)`` — bare publish when the resp exists."""
        if dev_id is None or len(dev_id) == 0:
            return
        resp = self._get_resp(dev_id)
        if resp is not None:
            self.send_awake(resp)

    # --- checkAwakeStatus -----------------------------------------------------------

    def check_awake_status(self, dev_id: str) -> None:
        """``bdpdqbp(String)`` — Business
        ``m.thing.device.low.power.connect.batch.get`` call; the
        ``$qddqppb`` listener logic is inlined here. The Business field
        is unconditionally initialised in Java ``<clinit>`` — a missing
        seam raises, which ``_start_wake_task``'s catch maps to
        ``UNSUPPORT``."""
        manager = self

        class _Listener:
            def on_failure(self, biz_response, results, api_name):
                pass  # logged only

            def on_success(self, biz_response, results, api_name):
                if results is None or len(results) == 0:
                    manager.dispatch_result(dev_id, LowPowerAwakeRsp.UNSUPPORT)
                    return
                result = results[0]
                if not result.low_power_connect:
                    # "Already woken up."
                    manager.awake_flags[dev_id] = True
                    manager.awake_change_times[dev_id] = result.last_connect_change_time
                    manager.dispatch_result(dev_id, LowPowerAwakeRsp.SUCCESS)

        self._check_awake([dev_id], _Listener())

    # --- teardown ------------------------------------------------------------------

    def release(self, destroy: bool) -> None:
        """``bdpdqbp(Z)`` — clears the task map always; on destroy also
        tears down the Business + callback registry."""
        if self.wake_tasks:
            self.wake_tasks.clear()
        if destroy and self.callbacks:
            self.callbacks.clear()
        for m in (
            self.awake_flags,
            self.awake_change_times,
            self.wake_deadlines,
        ):
            if m:
                m.clear()

    # --- internals ------------------------------------------------------------------

    def _get_resp(self, dev_id: str | None) -> DeviceRespBean | None:
        if self.dev_cache is None or dev_id is None:
            return None
        return self.dev_cache.get_dev_resp_bean(dev_id)
