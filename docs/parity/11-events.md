# 11 — Listener & event flow: inbound DP update pipeline

Canonical classes:

- `smali_classes4/com/thingclips/smart/sdk/api/IDevListener.smali` — public
  listener API.
- `smali_classes3/com/thingclips/sdk/device/qbqqdqq.smali` — event center
  (EventBus subscriber + listener fan-out), 6318 lines.
- `smali_classes3/com/thingclips/sdk/device/ppdpppq.smali` — per-device
  event processor, 912 lines.
- `smali_classes3/com/thingclips/sdk/device/qqdqbpb.smali` — gateway
  variant (sub-device routing).
- `smali_classes3/com/thingclips/sdk/device/ppqqqpb.smali` —
  `DevListCacheManager` (DeviceRespBean/DeviceBean cache).
- `smali/com/popur/android/feature/device/DeviceDpStringParser.smali` —
  app-side dpStr → Map parser.
- `smali/com/popur/android/feature/device/DeviceDpDataNormalizer.smali` —
  app-side inbound normalizer.
- `smali/com/popur/android/feature/home/HomeViewModel.smali` — `q()`
  merge into per-device dp-state map.

## `IDevListener` API (IDevListener.smali:6-20)

```
onDpUpdate(String devId, String dpsJson)
onDevInfoUpdate(String devId)
onRemoved(String devId)
onStatusChanged(String devId, boolean online)
onNetworkStatusChanged(String devId, boolean)
```

Extension interfaces observed in dispatch:

- `IExtDevListener.onDpUpdate(String devId, DpsInfoBean)` —
  `DpsInfoBean{dps: String, dpsTime: Map<String,Long>,
  dpsSource: int}` (ppdpppq.smali:147-159).
- `IDevExtendListener.onDpUpdate(String devId, String json,
  Map<Long>?, int)` / `onStatusChanged(String, boolean, int)`
  (qbqqdqq.smali:1296-1310, 5661-5667).
- `ISubDevListener.onSubDevDpUpdate(String nodeId, String json)`
  (qqdqbpb.smali:674-720).
- `IThingDevEventListener.onDpUpdate(int from, String devId, Map meta,
  String dpsJson)` / `onStatusChanged(int, String, int)` — internal bus
  (qbqqdqq.smali:712, 1469+).

## Inbound dispatch chain

```
MQTT/LAN decode (mqtt ppdpppq pv-routed handlers)
  → ThingEventBus post: DpUpdateEventModel | DeviceDpsUpdateEventModel |
      ZigbeeSubDevDpUpdateEventModel | MeshDpUpdateEventModel
  → qbqqdqq.onEvent*(...)  (qbqqdqq.smali:1796-4073)
  → qbqqdqq.dispatchDpEvent/bdpdqbp(from, devId, meshId, nodeId,
      dpsTime, dpsJson)                     (619-719)
      1. legacy fan-out bdpdqbp(devId, json, dpsTime, from)
         → every registered IDevListener:
             IDevExtendListener → onDpUpdate(devId, json, map, from)
             else             → onDpUpdate(devId, json)
      2. per-device listeners bdpdqbp(devId, meshId, nodeId)
         → IThingDevEventListener.onDpUpdate(from, devId,
             meta{"dpsTime": dpsTime}, json)
  → ppdpppq.onDpUpdate(from, devId, meta, dpStr)   (294-729)
      - bdpdqbp(from, devId) intercept hook (default false; subclasses
        may drop the event)
      - meta["dpsTime"] extracted (Map<String,Long>)
      - isFromCloud = (from == 3 || from == 5)
      - bdpdqbp(devId, dpStr, dpsTime, isFromCloud)   (41-169):
          if listener != null && dpStr non-empty && dpStr != "{}":
            IExtDevListener → onDpUpdate(devId,
                DpsInfoBean(dpStr, dpsTime){dpsSource=isFromCloud})
            else → IDevListener.onDpUpdate(devId, dpStr)
```

`from` codes observed: `DpUpdateEventModel.isFromCloud` → 3 else 4
(qbqqdqq.smali:3708-3780); `ZigbeeSubDevDpUpdateEventModel` → 4
(3993-4073); intercept passes through only `from==3 || from==5` as
"fromCloud" to `DpsInfoBean.dpsSource`.

`onDevInfoUpdate(devId, _, cmd)` (ppdpppq.smali:183-292): devId must equal
registered devId; `cmd==1` → `onRemoved`; `cmd==2` → `onDevInfoUpdate`.

### Sub-device routing (qqdqbpb.onDpUpdate, 674-730)

- meta carries `nodeId`/`meshId` strings.
- If a `ISubDevListener` is registered: event meshId == gateway meshId →
  `onSubDevDpUpdate(nodeId, json)`; else look up `DeviceRespBean` by the
  event devId and if `deviceTopo.parentDevId` == gateway devId →
  `onSubDevDpUpdate(respBean.nodeId, json)`; else drop.
- Without sub-listener: forward only if event devId == registered devId
  OR event devId resolves to a sub-device whose nodeId matches meta —
  then `super.onDpUpdate`.

## Device cache (`DevListCacheManager` = ppqqqpb)

Python port: `pypopur.sdk.device_cache`.

Stores (ppqqqpb fields):
- `pdqppqb` — devId → `DeviceRespBean` (main map)
- `pbbppqb` — uuid → devId
- `bppdpdq` — sub-device index: `parentDevId + "parentId/noteId" + nodeId`
  → devId, and `meshId + "parentId/noteId" + nodeId` → devId; nodeId
  len==2 padded `"00"+nodeId` on both write (`pdqppqb` 5259-5454) and
  read (`getSubDev` 3973-4116). Also plain `communicationNode → devId`.
- `pppbppp` — `meshId + "device/meshId/mac" + mac` → devId
- `qpppdqb` — communicationNode → zigbee timestamp (millis)
- `pbddddb` — devId → DeviceBean (new-cache mode only, `bdpdqbp:Z`)

`addDev`/`addDevList` (328-1618): per bean — skip null/null-devId;
index uuid (warn "uuid is null" when empty); `_index_sub_dev`;
`_zigbee_inherit` (`qddqppb` 5456-5754): skipped when
`protocolAttribute & 0x2`, needs `communicationNode != devId`,
`qpppdqb[node]` within 60000 ms, product `hasZigBee`, existing cached
bean → new bean inherits cached `dps` + `cloudOnline`.

`getDev(devId)` (3393-3471): new-cache → `pbddddb` hit returns; else
`pdqppqb[devId]` → respBean; product lookup via
`pbqdddb` key `productId + "_" + (productVer || "1.0.0")`
(empty productId → `""`); product null → null; else `devRespWrap`.

`devRespWrap` (1997-3370) copies ~60 fields; comm-module loop sets
`has{Mqtt,Ble,Lan,Sigmesh,ThingMesh}Communication` per mode type and
`pv` = MQTT mode's pv, else BLE's, else HTTP's. `isOnline` ←
`cloudOnline`. `DeviceBean.getAttribute()` returns
`productBean.attribute` (DeviceBean.smali 714-764) — **product**
attribute, used by the low-power dedup check (`0x1000`).

`DeviceRespBean.getDps()` (446-560): lazily calls
`IThingLitePresenter.decodeRaw(devId, dps)` once under lock, then sets
`isRawDecoded` — only inside the `plugin != null` branch. `getDpsTime`
has no `dataPointInfo` null-check → NPE (port: AttributeError).

`DeviceDataManager` (`ddpdbbp`): `getDps(devId)` → respBean.getDps()
(lazy decode); `getDp` = dps.get; `getSchemaBean(devId)` → product
`SchemaInfo.getSchemaMap` (dpId-keyed, 1681-1753);
`getDpCodeSchemaMap` → code-keyed (1191-1306).

- `updateDevList`, `updateSubDevDps(respBean|devId, nodeId, map)`
  (5869-6140) merge inbound dps into the cached `DeviceRespBean.dps` —
  **the cache merge happens inside the decode/post stage before the
  event reaches listeners**; the listener receives the raw `dps` JSON
  string of that update only. `updateSubDevDps` uses lazy `getDps()`,
  creates+attaches the map when null (5957-6030).

## App-side receive path

`HomeViewModel.createDeviceListener` (HomeViewModel
$createDeviceListener$1.smali) — anonymous `IDevListener`; every callback
launches a `viewModelScope` coroutine. `onDpUpdate(devId, dpStr)`
coroutine (`...$onDpUpdate$1.smali`):

1. Log `🔄 设备DP数据更新: <devId>, 数据: <dpStr>`.
2. Mark `DeviceInitStatus` (per-devId init tracker map).
3. `DeviceDpStringParser.a(dpStr)` → Map (below).
4. `HomeViewModel.q(devId, map, p3, p4)`.
5. Exceptions → error logs `更新设备DP状态失败` / `处理DP数据更新失败`.

### `DeviceDpStringParser.a` (whole file, 36-709)

1. blank → `emptyMap`.
2. `new JSONObject(dpStr)` → copy every key/value into a map. If the
   parse throws, or result is empty → legacy fallback.
3. Legacy fallback: trim → strip leading `{` / trailing `}` → split
   `,` → each part split `:` must yield exactly 2 →
   `key = trim + unquote`; value = trim →
   `"true"`→`true`, `"false"`→`false`, `"..."`-quoted → string,
   `toIntOrNull`→Int, `toDoubleOrNull`→Double, else raw string.
   Any exception → `emptyMap`.

### `DeviceDpDataNormalizer.a` (30-133)

1. Empty → return as-is.
2. `mutableCopy` → `Dp101RunModeSet.applyToMap` (see 09-dp-model.md).
3. `Dp102SystemSettings.parseSmoothSpreadCount(map["102"])` non-null →
   `map["__dp102_setting_smooth__"] = int`.

### `HomeViewModel.q(devId, dps, p3, p4)` (7105+)

1. Empty → return.
2. Normalize via `DeviceDpDataNormalizer`.
3. `pending = q[devId]` — `PendingAction{a=action, b=expectedRunningStatus,
   c=snapshotMap}`. If present →
   `Dp101RunModeSet.mergeDuringPendingCleaningAction(normalized,
   snapshot, action, expected)`; log `采纳设备上报` (adopt device report)
   vs `保留乐观补丁` (keep optimistic patch).
4. `j(devId, runningStatus)` — pending bookkeeping.
5. `n[devId]` = device dp-state map (mutable copy or new LinkedHashMap).
   If `p4 == true && pending == null` → `clear()` first (full-sync
   semantics). Then `putAll(merged)` → `Dp101RunModeSet.applyToMap` →
   store back into `n[devId]`.
6. `CleaningProgressManager.g(devId, mergedMap, p3)`.
7. runningStatus transitions (`clean_start`/`clean_pause`) update
   pending-action state / cleaning progress.

The `PendingAction` record is created by the control path when a
cleaning command is sent (expected runningStatus recorded so a stale
device report can't clobber the optimistic UI state).

## Other `onEvent*` observed in qbqqdqq (for completeness)

`NetWorkStatusEventModel`, `MeshLocalOnlineStatusReport/Update`,
`DeviceOnlineStatusEventModel`, `DevUpdateEventModel`,
`DeviceUpdateEventModel`, `SubDeviceRelationUpdateEventModel`,
`MeshDeviceRelationUpdateEventModel`, `MeshBatchReportEventModel`,
`MqttConnectStatusEventModel` — each routes to the matching
`IThingDevEventListener`/`IDevListener` fan-out or cache update.

## Open items

- Exact set of `from` codes (3/4/5 and any others) and which decoders
  post which model — enumerate when implementing inbound MQTT decode.
- `qbqqdqq.bdpdqbp(int,String,Map,String)` mid-section (meta merge
  before listener dispatch) — verify `dpsTime` wrapping.
- `DeviceRespBean.dps` merge ordering inside decoders (LAN vs MQTT
  ordering, `dpsTime` updates) — Phase-1 implementation detail.
- Whether `p3`/`p4` in `HomeViewModel.q` map to "isFullSync"/"fromInit"
  — confirm from call sites when rebuilding app-layer state.
