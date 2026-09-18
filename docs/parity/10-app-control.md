# 04 — App-level device control (Popur layer)

Classes:
- `com.popur.android.feature.device.UnifiedDeviceControlManager`
  (smali/com/popur/android/feature/device/UnifiedDeviceControlManager.smali,
  11237 lines)
- `com.popur.android.feature.device.UnifiedDeviceControlHelper`
  (…/UnifiedDeviceControlHelper.smali, 20671 lines)
- `com.popur.android.feature.device.DeviceDpStringParser`
  (…/DeviceDpStringParser.smali, 709 lines)

The app does NOT talk to `qqdbbpp` directly. It calls
`ThingHomeSdk.newDeviceInstance(devId)` → `IThingDevice` and invokes methods
**reflectively** (obfuscation-resilient). The SDK dispatch chain (doc 01) runs
underneath `publishDps`.

## Device instance cache

`UnifiedDeviceControlManager.b` = `LinkedHashMap<devId, deviceInstance>`
(populated by `j(devId)` = `newDeviceInstance`, Manager.smali:6411-6745).
`j` initializes on miss; init failure → callers emit
`onError("DEVICE_NOT_FOUND", "设备实例初始化失败")`
(Manager.smali:6870-6909, Helper.smali:5335-5374).

## sendDeviceCommand — `Helper.I(devId, dps, cont)` (Helper.smali:4729-5832)

1. Filter `dps`: copy only entries with non-null values
   (4931-4980). If any were dropped → return
   `Result.failure(IllegalArgumentException("设备控制失败: <devId>,
   原始DPS: <map>"))` — no network call.
2. `suspendCancellableCoroutine` → manager send block (5190-5718):
   a. resolve/init device instance (see above).
   b. `g(device)` — debug dump of class methods (publish*/send*/raw…).
   c. Passthrough detection: if `dps.values()` is non-empty AND **any value
      is `byte[]`** → "检测到透传型数据，优先尝试透传方法"
      (5405-5491). Try order: `q` → `o` → `p` → `m`.
      Otherwise try: `p` → `o` → `m`.
   d. All failed → `onError("NO_CONTROL_METHOD", "无法找到可用的控制方法")`.
   e. Exception → `onError("COMMAND_EXCEPTION", "控制指令异常: <msg>")` +
      CrashReporter.recordException.
3. On success → `DeviceRepository.P(devId, dps, cont)` — post-write hook
   (optimistic DP state update; see 07-state).

### Send strategies (Manager.smali)

- `p` (8398-8582) — PRIMARY:
  `device.publishDps(d(dps), proxy(IResultCallback))`.
  Proxy = `Proxy.newProxyInstance` with `q0` handler (q0.smali:54-312):
  `onError(code,msg)` → callback.onError verbatim;
  `onSuccess()` → callback.onSuccess.
- `o` (3834-4641) — tries `publishDps(String)`, then `publishDps(Map)`,
  then `publishDps(JSONObject)` (in that order; first found is invoked with
  `d(dps)` for String / map / JSONObject).
- `q` (8584-9826) — passthrough: scans device class for raw-ish methods
  (names containing raw/command/hex/bytes/data-ish per 2754-2916 area),
  sends byte[] payloads directly. Used only when a byte[] DP is present.
- `m` (3367-3832) — brute force: every method whose lowercase name contains
  `publish`/`send`/`control` with ≤2 params; each single-arg method invoked
  with `d(dps)` JSON string; first non-throwing wins → onSuccess.

### `d(Map)` — DP map → JSON string (Manager.smali:512-~840)

Manual serializer (NOT org.json):
`{` `"k":v` `,` … `}` — String → `"v"` (no escaping), Boolean → `true/false`,
Number → toString, `byte[]` → `"<base64 NO_WRAP>"`, other → TBD (tail of
method ~830-1150: check JSONObject/Map/list handling).

## Batch query — `Helper` queryDeviceDp path

`Manager.k(devId, cb)` (6745-7057): resolve/init device instance then
**immediately `cb.onSuccess()`** — the "batch query" is satisfied by the
listener-driven state (it just ensures the instance+listener exist).
Log: "开始批量查询设备所有DP状态" then "已触发全量DP状态刷新（依赖监听器回调）".
`Manager.n(device, fetchedCb)` (7834-8396): applies a fetched dps map into
DeviceState then `onSuccess` (used by queryDeviceDp continuation).

## DeviceState (inner class)

`UnifiedDeviceControlManager$DeviceState` — fields `(int, String devId,
boolean)` ctor + copy-method `a(state, online?, Map dps, long ts, bool, bool,
mask)` (8246: mask 0x71; 5967: mask 0x73). Holds `c` = dps map.
Published via `v(devId, state)` (11126-…) into a `MutableStateFlow<Map<devId,
DeviceState>>`.

## Listeners — IDevListener via reflection

`Manager.l(devId, DeviceListener)` (7059-7834) / `r` (9826-10270) /
`s` (10270-10548) / `t` (10548-10829):

- `r`: probe `Class.forName` over interface candidates in order:
  `com.thingclips.smart.home.sdk.callback.IDevListener`,
  `com.thingclips.smart.sdk.callback.IDevListener`,
  `com.thingclips.smart.home.sdk.api.IDevListener`,
  `com.thingclips.smart.sdk.api.IDevListener`,
  `com.thingclips.smart.sdk.api.IDeviceListener`,
  `com.tuya.smart.sdk.api.IDevListener`,
  `com.tuya.smart.sdk.api.IDeviceListener` (9849-9879).
  First found → `Proxy.newProxyInstance` with `q0(mode=0)` → invoke
  `registerDevListener` or `registerDeviceListener` on the device instance
  (10056-10066).
- `u(devId)` (10829-11126): `unRegisterDevListener` (string at 10973).
- `q0` mode-0 forwards every proxy callback to
  `i(methodName, args, bridge)` (425 in q0).

### `i` — createMulticastBridge dispatch (4800-6411)

On `onDpUpdate` (5185-6069):
1. `c(args)` → devId string (arg0); arg1: String → use; Map → `d(map)`;
   else `toString` (5303+).
2. Update StateFlow DeviceState: existing or new
   `DeviceState(?, devId, ?)`; parse dps string:
   - `new JSONObject(str)` → entries → LinkedHashMap;
   - on parse failure → `DeviceDpStringParser.a(str)` manual parse → putAll.
3. `merged = state.dps.toMutableMap(); merged.putAll(newDps)` — **new DPs
   overwrite, absent keys preserved** (5929-5941).
4. `DeviceState.a(..., dps=merged, ts=now, mask 0x73)` → `v(devId, state)`.
5. Forward `bridge.onDpUpdate(devId, dpsString)` to app listener (6064).

Also handles `onDevInfoUpdate` (4942), `onNetworkStatusChanged` (5008,
updates online flag), `onStatusChanged` (6073), `onRemoved` (6248, cleans
device resources).

## TBD

- `d` serializer tail (830-1150): JSONObject/Map/other value handling.
- `DeviceDpStringParser.a` grammar (manual dps-string parser).
- `c(args)` exact arg extraction.
- `q` passthrough method list + payload marshaling (byte[] → hex? raw?).
- `DeviceState` ctor arg meaning (int field) + copy-mask semantics.
- `Manager.l` vs `r`/`s`/`t` — which registration path is primary and when
  the others are fallbacks.
- `Helper` per-command methods (J,K,L,…Z0 ≈ 80 of them): map each to its DP
  code + value shape — big mechanical job, do during Phase 0f with the DP
  schema list.
