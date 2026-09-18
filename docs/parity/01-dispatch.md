# 01 — Command dispatch pipeline

## publishDps entry (2-arg)

`AbsThingDevice.publishDps(String dpsJson, IResultCallback)`
(smali_classes3/com/thingclips/sdk/device/presenter/AbsThingDevice.smali:2476-2645)

1. Look up `DeviceRespBean` for `mDevId`. If `communication.dataModel ==
   DataModelType.THING_MODEL` → convert dps via `qqbbddb.pdqppqb(devId, dps)`
   (DP→Thing-model conversion), then if `thingModel` bean present →
   `publishThingMessageWithType(PROPERTY, convertedDps, cb)`; else async-fetch
   thing model via `ThingOSDevice.getDeviceOperator().getThingModelWithProductId`
   then continue. (AbsThingDevice.smali:2514-2584)
2. Else: fetch `communication.communicationModes` list. If BLE plugin present,
   use `IThingBleManager.orderLocalCommunicationList(respBean)` instead; if
   bean null → empty list. (AbsThingDevice.smali:2587-2641)
3. `publishDpsInPipeline(dps, modes, cb)`.

## publishDps with explicit mode enum

`publishDps(dps, ThingDevicePublishModeEnum, cb)` (AbsThingDevice.smali:2647-2739)

Ordinal dispatch (bppdpdq.bdpdqbp[] switch map):
- case 1 → `publishDpsByCloud` — requires `bpbqqdq.pdqppqb()` (cloud-online
  check) else error `10202 "device is not in cloud online"`, then
  `mDevModel.bppdpdq(dps, cb)` (internet send). (826-877)
- case 2 → `publishDpsByIntranet` — requires `mDevModel.isIntranetControl()`
  else `10201 "device is not in intranet online"`, then
  `mDevModel.intranetControl(dps, cb)`. (879-931)
- case 3 → 2-arg `publishDps` (pipeline).
- case 4 → `mDevModel.qddqppb("", dps, cb)`.
- case 5 → `mDevModel.bppdpdq("", dps, cb)` (3-arg variant).

## publishDps with channel list (3-arg)

`publishDps(dpsJson, channelListJson, cb)` (AbsThingDevice.smali:2741-3022)

- Parse channelListJson as JSON array of ints; keep entries that map to a
  known `CommunicationEnum`; log+drop unknown.
- Empty → `qqpppdp.bppdpdq().bppdpdq(devId)` then error
  `301001 "communication_types_illegal"`.
- Intersect requested types with device's `communicationModes` in REQUESTED
  order; a requested YU_MQTT type synthesizes a `CommunicationModuleT(type=12)`
  even if absent from the device list.
- Empty intersection or null device list → `301001 "communication_types_illegal"`.
- Else `publishDpsInPipeline`.

## publishDpsInPipeline

(AbsThingDevice.smali:933-1639)

1. `JSON.parseObject(dps)` into LinkedHashMap; `DevUtil.checkSendCommond(devId,
   map)` → false ⇒ error `11001 "command error,data type verification failed."`
2. modes null/empty ⇒ error `11001 "communication types illegal"`.
3. If first mode is BLE and last is not YU_MQTT → append YU_MQTT module to end
   (log "ble communication first, add yu mqtt communication to the end.").
4. `checkDirectGateway(modes)` (AbsThingDevice.smali:76-717) — sub-device
   BLE promotion:
   - no-op unless this device's `deviceTopo.parentDevId` is non-empty.
   - `parentSupportStruct` = parent `DeviceBean.deviceBizPropBean.
     bluetoothCapability` non-empty AND `ThingBleUtil.
     parseBleDeviceCapability(cap, 19)` (bit 19).
   - `bleOnline` = `DevUtil.isSingleBleLocalOnline(parentDevId)`.
   - `isParentBLEFirst` = parent's `communicationModes` non-empty and
     first entry type == BLE.
   - If `bleOnline && parentSupportStruct`: if `modes` already has a BLE
     entry and `isParentBLEFirst` → remove and re-insert at index 0; if
     absent → insert new `CommunicationModuleT(BLE)` at index 0 when
     `isParentBLEFirst`, else append at end.
5. Build handler chain in declared-mode order — switch on
   `CommunicationEnum.getEnum(type)`:

   | enum | handler | extra |
   |---|---|---|
   | MQTT | `dppdqpp` | |
   | HTTP | `dbbpdqp` | |
   | THING_MATTER | `qdqbdbd` | |
   | LAN | `bddqdbd` | pre-attached follower `qdqbdbd` |
   | BLE | `bqpdbqq` | |
   | SIGMESH | `qqppqqd` | |
   | THING_MESH | `pdpdpqp` | |
   | YU_MQTT | `bqpdbqq` | pre-attached follower `dqqbppb` |
   | THING_BEACON | `qpppqdb` | |
   | CLOUD_MODE | `qbdppbq` | |

   Chain = singly linked list via field `qqqbbbd.bdpdqbp`; each new handler is
   appended at the current tail (so a pre-attached follower stays attached
   before later modes).
6. Head handler `bdpdqbp(dps, cb)`; if no handler built ⇒ `11005 "send error"`.

## Handler base `qqqbbbd` ("ThingCommPipeline")

(smali_classes3/com/thingclips/sdk/device/qqqbbbd.smali:44-172)

`bdpdqbp(dps, cb)`:
- if `bppdpdq()` (channel available): analytics hook
  `qqpppdp.bdpdqbp(devId, dps, this)`, then `pdqppqb(dps, wrap(cb))`.
  The wrapper (`qqqbbbd$bdpdqbp`) forwards onSuccess/onError verbatim and
  reports analytics (`pppbppp` on success, `bdpdqbp(devId,code,msg)` on error).
  NOTE: the base wrapper does NOT advance to the next handler on send error —
  advancing on unavailability happens in `bdpdqbp`; send-failure fallback is
  implemented inside specific handlers' own callbacks (see LAN below).
- if not available → `next.bdpdqbp(dps, cb)`; no next ⇒ analytics
  `qddqppb(devId)` + `11005 "send error,no channel available."`.

## LAN handler `bddqdbd` ("ThingLanCommPipeline")

(smali_classes3/com/thingclips/sdk/device/bddqdbd.smali + $bdpdqbp)

- available ⇔ `mDevModel.isIntranetControl()`.
- send: post watchdog runnable on main Handler at +500 ms; call
  `mDevModel.intranetControl(dps, wrappedCb)` with `boolean[1] done={false}`.
  - watchdog fires with `done==false`: log "LAN request timeout, fallback to
    internet"; call `mDevModel.bppdpdq(dps, cb)` — direct internet send,
    bypassing the chain. The in-flight LAN call is NOT cancelled.
  - wrappedCb.onError: `done=true`, cancel watchdog, then ALSO calls
    `mDevModel.bppdpdq(dps, cb)` (internet fallback), plus a StatUtils event
    unless `msg.endsWith("#")`. So a LAN failure → internet retry. A LAN
    timeout-then-late-error → internet send twice (once by watchdog, once by
    onError).
  - wrappedCb.onSuccess: `done=true`, cancel watchdog, forward onSuccess.
    (LAN success after watchdog fired ⇒ the internet send already went out —
    duplicate command possible; faithful behavior.)

## MQTT handler `dppdqpp` ("ThingMqttCommPipeline")

- available ⇔ `NetworkUtil.networkAvailable(ctx) && mDevModel.isCloudOnline()`.
- send: `bpbqqdq.bdpdqbp(devId, 8000L, wrappedThingResultCb)` — the device-comm
  manager MQTT publish with 8 s timeout. `dppdqpp$bdpdqbp` (lines 64-219):
  both `bdpdqbp(LowPowerAwakeRsp)` (success) and `onError(code, msg)` call
  `mDevModel.bppdpdq(dps, cb)` — i.e. the MQTT handler stage is a
  wake/publish attempt; the actual command send always goes through the
  internet-send path (`bppdpdq` → server control). It never calls the
  caller's onError nor advances the chain directly.

## HTTP handler `dbbpdqp`

- available ⇔ `mDevModel != null` (always true).
- send: `mDevModel.sendDpsByApi(devId, dps, cb)`.

## CLOUD_MODE handler `qbdppbq`

- available ⇔ `mDevModel != null`.
- send: `mDevModel.sendCloudDpsByApi(devId, dps, cb)`.

## DevModel `qpbpqpq` ("DevModel")

(smali_classes3/com/thingclips/sdk/device/qpbpqpq.smali)

- `isIntranetControl()` (1129-1273): IThingHardwarePlugin →
  `IThingDevListCacheManager.getDev(devId)` → `hardware.getDevId(
  device.communicationId)` → `HgwBean`; true iff `active == ACTIVED` or
  `LOCAL_ACTIVED`.
- `isCloudOnline()` (984-1127): bean from `bpbqqdq.getDev(devId)`; if
  `communicationId != devId` → require gateway dev online AND
  `bean.isCloudOnline()`; else `bean.isCloudOnline()`.
- `intranetControl(dps, cb)` → `dbqqppp.pdqppqb(dps, wrapped)` (959-982).
- `bppdpdq(dps, cb)` → `dbqqppp.bdpdqbp(dps, 0, cb)` — internet send (469-480).
- `sendDpsByApi(devId, dps, cb)` (2126-2190): `bdpdqbp(dps, devId)` =
  parse dps JSON → LinkedHashMap → `DevUtil.checkSendCommond` (fail →
  null) → `DevUtil.encodeRaw`; empty/null ⇒ `onError("11001", null)`;
  else `dbppbbp.pbbppqb(devId, dps, listener)` — ATOP
  **`thing.m.nb.device.dp.publish` v1.0**, postData `{devId, dps}`
  (dbppbbp.smali).
- `sendCloudDpsByApi` (2060-2124): same transform, then
  `dbppbbp.pppbppp(...)` — ATOP **`thing.m.device.dp.publish` v1.0**,
  postData `{devId, dps}`.
- `bdpdqbp(cb)` device-alive check (209-241): if `bdpdqbp()` (schema
  missing) → `onError("11002","device is removed")`; else
  `dbppbbp.qpppdqb(devId, listener)` — ATOP **`s.m.dev.dp.get` v1.0**
  with `{gwId?, devId}`.
- `bdpdqbp()` (417-467): true iff no respBean OR no ProductBean for
  productId+productVer — i.e., "schema missing" signal.

## Command validation — `DevUtil.checkSendCommond`

(smali_classes3/com/thingclips/sdk/device/utils/DevUtil.smali:724-1132)

Wrapper `(devId, map)`: schema = `bpbqqdq.getSchema(devId)`; calls inner
`(schemaMap, map)`; any exception → false.
Inner `(schemaMap, map)` (767-1132):
- schemaMap null ⇒ **false**
- per DP entry: null value ⇒ skip; dpId absent from schema ⇒ skip
- schema `mode == "ro"` ⇒ FAIL
- type `obj` + schemaType:
  - `bool` ⇒ Boolean, or String `"toggle"` allowed
  - `enum` ⇒ String ∈ `toEnumSchema(property).range` (schema bean or
    range null ⇒ FAIL)
  - `string` ⇒ len ≤ maxlen
  - `value` ⇒ **Integer only** (Long → ClassCastException → wrapper
    catches → false), min ≤ v ≤ max
  - `bitmap` ⇒ Integer, 0 ≤ v < 1<<maxlen
- type `raw` ⇒ String, `HexUtil.checkHexString` AND even length
- other type ⇒ String nonempty

## Receive validation — `DevUtil.checkReceiveCommond`

(DevUtil.smali:27-722). Same per-type rules as send **except**:
- schema map null ⇒ **true**
- no `ro` check
- `value` accepts Integer **or** Long (other numeric types → sentinel
  MAX_VALUE → FAIL)
- null values are NOT skipped — they fail instanceof/cast checks ⇒ false

## RAW wire conversion — `DevUtil.encodeRaw` / `decodeRaw`

- Send side (`encodeRaw`, DevUtil.smali:1463-1744): for each schema-`raw` DP,
  value hex string → `HexUtil.hexStringToBytes` → `Base64.encodeBase64` →
  replace value with Base64 text; then `JSON.toJSONString(map)` is the wire
  payload (the 3-arg variant returns original `p1` string if no raw DP
  matched). So **on the wire RAW DPs are Base64, not hex**.
- Receive side (`decodeRaw`, DevUtil.smali:1206-1390): for each schema-`raw`
  DP, `value.getBytes()` → `android.util.Base64.decode(flags=0)` →
  `HexUtil.bytesToHexString` (per-byte `Integer.toHexString`, zero-padded —
  **lowercase**; HexUtil.smali:89-196) → hex text back into the dps map.
  Non-decodable → warn; if decode produced empty while source was non-empty,
  the value is NOT overwritten.

## BLE / YU_MQTT handlers

`bqpdbqq` (BLE, bqpdbqq.smali): available ⇔ `IThingBlePlugin` present &&
`bleManager.isBleLocalOnline(devId)`; send →
`IThingBleManager.publishDps(devId, dps, cb)`. (Also instantiated for the
YU_MQTT chain slot — its `dqqbppb` follower does the actual YU send.)

`dqqbppb` (YU_MQTT, dqqbppb.smali): available ⇔ `IYuPlugin` present &&
`mqttChannel != null` && `bpbqqdq.pdqppqb()` (MQTT connected) &&
`yuChannel.getStatus(devId).isOnline()`; send →
`yuChannel.sendDps(devId, dps, cb)`; null channel → `11005 "yu channel
is null"`. For an S7-class WiFi device without the BLE/Yu plugin these
are simply unavailable and the chain skips them.

## TBD follow-ups

- (none remaining for the S7 send path; native LAN internals tracked in
  05-mqtt.md)
