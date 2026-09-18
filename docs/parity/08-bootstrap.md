# Parity Spec — 08: Home & Device Bootstrap

Canonical source: `popur-research/apktool` smali (jadx is incomplete for
these classes). All paths below are relative to
`popur-research/apktool/`; `s3` = `smali_classes3`, `s` = `smali`.

## App → SDK call surface

The Popur app reaches SDK managers via reflection (`Class.getMethod`)
and wraps callback interfaces with `java.lang.reflect.Proxy` inside
`SafeContinuation`s.

- Home list: `ThingHomeSdk.getHomeManagerInstance().queryHomeList(
  IThingGetHomeListCallback)` — called from `LoginViewModel.smali:721`,
  `DeviceRepository` (15023-15092 "getHomeListWithDetails", 29730,
  30176), `HomeViewModel` (4070-4139), `PetManagementViewModel` (2387),
  `DevicePairingViewModel` (1198). Also
  `com/popur/loginregister/utils/HomeManager.smali:254`.
- Home instance: `ThingHomeSdk.newHomeInstance(long homeId)` →
  `com.thingclips.sdk.home.o000Oo0` (implements `IThingHome`,
  `s3/com/thingclips/sdk/home/o000Oo0.smali:6`).
- Network fetch: `home.getHomeDetail(IThingHomeResultCallback)`
  (`DeviceRepository` 15406-15600).
- Cache read: `home.getHomeDetailBean().getDeviceList()`
  (`DeviceRepository` 10342-10490).

## `getHomeDetail` internals

`o000Oo0.getHomeDetail` → `o00Oo0.getHomeDetail` (`s3/.../o00Oo0.smali:1048`)
→ `OooOOO.OooO0O0(gid, cb)` (HomeCacheModel, `s3/.../OooOOO.smali:3230`):

1. **MQTT subscribe `m/ug/<gid>`** on `IThingMqttPlugin.
   getMqttServerInstance()` (OooOOO 3257-3271) — home-level update
   topic, subscribed before every home-detail fetch.
2. `OooO0OO(gid, cb)` (OooOOO 4395-4483) runs **3 parallel tasks**
   joined by `CountDownLatch(3)` (`OooOo$OooO0O0`), dispatched via
   `ThingExecutor.excutorDiscardOldestPolicy`:
   - `Oooo000` → `o00oO0o.OooO00o(gid, cb)` — **primary batch**
   - `o000OO` — "SecondaryHomeDetailInfoRequest": loads
     `deviceBizPropBeanList`, `productRefList`,
     `standardProductConfigs` **from local caches**
     (o000OO.smali 113-245) producing `ThingSecondaryListDataBean`
   - `o0OOO0o` → `o00oO0o.OooO0O0(gid, cb)` — local-device list:
     `m.life.app.smart.local.device.list` v1.1, postData
     `{homeId: gid, groupType: "homeGroup"}` →
     `ThingLocalDeviceListDataBean` (o00oO0o 1822-1871)
3. Results merge via `OooO0O0(ThingListDataBean,
   ThingSecondaryListDataBean, cb)` → `OooO00o` →
   `parseHomeDataCompat` (OooOOO 3305+).

## Primary batch — `thing.m.api.batch.invoke` v1.0

`o00oO0o.OooO00o(J, o000O000)` (o00oO0o.smali 226-320) builds exactly
8 ApiBeans **in this order**, then calls `OooO00o(gid, apis, cb)`
(1574-1654): `ApiParams("thing.m.api.batch.invoke","1.0")`,
postData `apis` = the list, postData `gid` = gid, `setGid(gid)`,
`setSessionRequire(true)`, `asyncArrayList(ApiResponeBean.class)`.

| # | ApiBean builder | API name | version | extra postData |
|---|---|---|---|---|
| 1 | `OooO00o(String gid)` | `m.life.my.group.device.sort.list` | 2.1 | `gid` (as String) |
| 2 | `OooO0Oo(J)` | `m.life.my.group.device.list` | 2.2 | `gid` |
| 3 | `OooO0o(J)` | `m.life.my.group.mesh.list` | 3.1 | `gid` |
| 4 | `OooO0o0(J)` | `m.life.my.group.device.group.list` | 4.3 | `gid` |
| 5 | `OooO0oo(J)` | `m.life.location.get` | 3.4 | `gid` |
| 6 | `OooO00o(J)` | `m.life.device.ref.info.my.list` | 7.2 | `gid` + `zigbeeGroup` flag (o00oO0o 124-147) |
| 7 | `OooO0Oo()` | `thing.m.my.shared.device.list` | 3.2 | — |
| 8 | `OooO0OO()` | `thing.m.my.shared.device.group.list` | 3.0 | — |

Response: `ArrayList<ApiResponeBean>` — each entry carries `api` name +
result; `OooO00o(J, ArrayList, o000O000)` (o00oO0o 359+) dispatches on
`getApi().hashCode()` into typed lists:
`DeviceRespBean` list, `GroupRespBean` list, mesh list, shared-device
lists, location, `HomeResponseBean`, etc. → `ThingListDataBean`.

Other single-shot APIs in `o00oO0o` (not part of getHomeDetail batch):
`thing.m.my.rule.device.list` 1.0, `thing.m.device.biz.prop.list` 1.0,
`thing.m.device.product.ref.list` 1.0, `m.life.device.ext.prop.list`
1.2, `m.life.product.ext.prop.list` 1.1, `m.life.product.standard.config.list`
1.1, `thing.m.product.ui.info.batch.get` 1.0,
`m.life.my.group.device.relation.list` 3.2.

## Merge into SDK caches — `parseHomeDataCompat` (OooOOO 3305+)

- `IThingDeviceListManager.addProductList(productBeen)` (3411-3419)
- shared devices: each `DeviceRespBean` in `deviceRespShareList` gets
  `setIsShare(true)` then `addDevList(...)` (3471-3575)
- `groupRespShareList`, mesh, room relations → `parseDevAndGroupRelation`
  steps 1-5 (log strings at 1033, 1109, 1262, 1343, 1417)
- local persistence keys: `s_home_detail<gid>`, `s_home_data_v1<gid>`,
  `s_home_data`, `s_home_list` via `PreferencesUtil` (OooOOO 3112,
  3290, 531, 1499)
- timing stats event `thing_sZGJhfSJ7as7OZaqkfU4ScTx92p9wy4X` (OooOOO 704)

## Device-record models

### `DeviceRespBean` (s3/.../interior/device/bean/DeviceRespBean.smali)

Fields: `accessType`, `activeTime`, `baseAttribute`,
`businessResponse`, `cloudOnline`, `communication`
(CommunicationModule), `dataPointInfo` (DataPointModule),
`devAttribute`, `devId`, `devKey`, `deviceBizPropBean`, `deviceTopo`,
`displayOrder`, `errorCode`, `gatewayVerCAD`, `homeDisplayOrder`,
`iconUrl`, `ip`, `isRawDecoded`, `lat`, `localKey`, `lon`, `mac`,
`meta`, `name`, `otaInfo`, `ownerId`, `productId`, `productInfo`,
`productRefBean`, `productStandardConfig`, `productVer`,
`protocolAttribute`, `resptime`, `runtimeEnv`, `secKey`, `shareInfo`,
`skills`, `thingModel`, `timezoneId`, `uuid`, `virtual`,
`virtualExperience`.

Bit constants: `BASE_ATTRIBUTE_THING_MATTER=0x80`,
`BASE_ATTRIBUTE_INFRARED_GATEWAY=0x100`,
`BASE_ATTRIBUTE_PRIVATE_MESH=0x200`; config bits `SIGMESH=0x1`,
`ZIGBEE=0x2`, `SUBPIECES=0x4`, `BEACON=0x8`, `THREAD=0x10`,
`ThingSMESH=0x20`, `BEACON_MESH=0x80`.

### `DeviceRespBean$CommunicationModule` (…$CommunicationModule.smali)

`communicationModes` (List — drives the publishDps channel chain in
01-dispatch), `communicationNode`, `connectionStatus`, `dataModel`,
`localCommunicationNode`, `localDataModel`, `localNodeId`,
`mqttTopicAttr`.

### `DeviceBean` (s4/.../smart/sdk/bean/DeviceBean.smali)

Public/key fields: `ability`, `accessType`, `appRnVersion`,
`attribute`, `baseAttribute`, `bv`, `cadv`, `category`,
`categoryCode`, `communicationId`, `connectionStatus`, `dataModel`,
`devAttribute`, `devId`, `devKey`, `devUpgradeStatus`,
`deviceBizPropBean`, `deviceCategory`, `displayDps`, `displayMsgs`,
`displayOrder`, `dpCodes`, `dpMaxTime`, `dpName`, `dps`, `dpsTime`,
`errorCode`, `faultDps`, `gwType`, `hasBleCommunication`,
`hasHttpCommunication`, `hasLanCommunication`, `hasMqttCommunication`,
`hasSigmeshCommunication`, `hasThingMeshCommunication`, `hgwBean`,
`homeDisplayOrder`, `i18nTime`, `iconUrl`, `ip`, `isLocalOnline`,
`isOnline`, `isShare`, `lat`, `localKey`, `lon`, `mUseNewCache`,
`mac`, `meshId`, `meta`, `mqttTopicAttr`, `name`, `nodeId`,
`openProxy`, `openRelay`, `otaUpgradeModes`, `ownerId`, `panelConfig`,
`parentDevId`, `parentId`, `productBean`, `productId`,
`productRefBean`, `productStandardConfig`, `productVer`,
`protocolAttribute`, `pv`, `quickOpDps`, `rnFind`, `runtimeEnv`,
`schema`, `schemaExt`, `schemaMap`, `secKey`, `sharedTime`, `skills`,
`supportAutoUpgrade`, `supportGroup`, `supportProxyAndRelay`,
`switchDp`, `thingModel`, `time`, `timezoneId`, `ui`, `uiConfig`.

## App-side device fields (reflection reads)

`DeviceRepository` reads these `DeviceBean`/`DeviceRespBean` fields via
its `F(obj, field)` / `I(obj)` reflection helpers (smali 5499-6620):
`devId`, `name`, `productId`, `iconUrl`, `mac`, `ip`, `isOnline`,
`isLocalOnline`, `isShare`, `virtual`, `supportGroup`, `timezoneId`,
`category`, `lon`, `lat`, `pv`, `bv`, `time`, `accessType`,
`isZigBeeWifi`, `hasZigBee`, `nodeId`, `meshId`, `dps`, `schemaMap`.

## App-side persistence keys (DataStore)

`DeviceRepository` ctor (839-951): `cleaning_start_time_<devId>`,
`device_dp_snapshot_<devId>`, `device_dp_snapshot_at_<devId>`,
`cleaning_progress_state_<devId>`, `device_name_history_<devId>`,
`device_color_<devId>`, `device_wifi_ssid_<devId>`,
`function_button_order_<devId>`, `device_list_order`,
`app_first_install_time`.

## Python port notes

- `bootstrap.fetch_home(home_id)` must: subscribe `m/ug/<gid>` topic,
  fire the 8-API batch + local-device list, merge into a
  `ThingListDataBean`-equivalent model, populate the device cache via
  the same precedence (product list → shared devices `isShare=True` →
  device list → groups → relations).
- The app's reflection-based field reads define the minimum
  `DeviceBean` attribute surface the Python model must expose.
