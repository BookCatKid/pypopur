# 07 — App state: DeviceRepository, home/device bootstrap, persistence

Class: `com.popur.android.core.data.repository.DeviceRepository`
(smali/com/popur/android/core/data/repository/DeviceRepository.smali, 45141
lines, obfuscated method names — cite lines).

All ThingClips SDK access is **reflective** (`Class.getMethod` on
`ThingHomeSdk` and returned instances) — an obfuscation-resilience pattern
the port should replicate semantically (call the equivalent interface).

## SDK surface used by DeviceRepository

| ThingHomeSdk method | Returned | Used for |
|---|---|---|
| `getUserInstance()` | IThingUser | `getUser()` → uid/username checks (8503, 8942, 30043) |
| `getHomeManagerInstance()` | IThingHomeManager | `queryHomeList(cb)` (15019-15047) |
| `newHomeInstance(homeId)` | IThingHome | `getHomeDetailBean()` + `getDeviceList()` (10342-10490); `getHomeDetail(cb)` async (15406+); shared device list |
| `getDataInstance()` | IThingDataManager | `getDeviceBean(devId)` (23102-23127) |
| `newDeviceInstance(devId)` | IThingDevice | `getDeviceBean`, `renameDevice`, `publishDps` (9423, 11574, 27263, 29272) |
| `getDeviceShareInstance()` | IThingDeviceShare | `addShareWithHomeId`, `confirmShareInviteShare`, `queryDevShareUserList`, `queryShareDevFromInfo`, `queryShareReceivedUserList`, `removeReceivedDevShare`, `disableDevShare` |
| `newOTAServiceInstance(devId)` | IThingOTAService | `getFirmwareUpgradeInfo` (4522) |
| `getWifiBackupManager(..)` | wifi backup | `getCurrentWifiInfo` (21097) |

Callback types: `IThingGetHomeListCallback`, `IThingHomeResultCallback`,
`IThingDataCallback`, `IResultCallback` — all via `Proxy.newProxyInstance`.

## Home bootstrap

- `queryHomeList` → `List<HomeBean>`; each HomeBean exposes `homeId`, `name`,
  `admin`, `geoName`, `deviceList`, `sharedDeviceList`, `groupList`,
  `sceneList` (getHomeListWithDetails$2$callback$1.smali).
- Per home: `getHomeDetail`/`getHomeDetailBean` → HomeDetailBean;
  `getDeviceList()` → `List<DeviceBean>`; `getSharedDeviceList()` for
  shared-in devices (getSharedDevicesFromHomeBean$result$1$callback$1).

## DeviceBean → app `Device` model — method `p` (5475-7738)

Reflective getter `F(bean, field)` reads:

```
devId, name, productId, iconUrl, mac, ip, isOnline, isLocalOnline,
isShare, virtual, supportGroup, timezoneId, category, lon, lat, pv, bv,
time, accessType, isZigBeeWifi, hasZigBee, nodeId, meshId, dps, schemaMap
```

Model classification (7140-7245), on name (v11) then productId? (v9) then
category (v1):
- name contains `s7` → "Popur S7"; contains `x5` → "Popur X5"
- second key contains `s7`/`x5` → same
- else category contains `pet` (or category null) → "Popur S7" (default arm)

Also `S(map, bool) → Pair` (1880-2525) — DP-state extraction helper used at
device build time.

## Local persistence keys (DataStore)

```
cleaning_progress_state_<devId>   cleaning_start_time_<devId>
device_dp_snapshot_<devId>        device_dp_snapshot_at_<devId>
device_list_order                 device_name_history_<devId>
device_color_<devId>              device_wifi_ssid_<devId>
function_button_order_<devId>     app_first_install_time
```

Related helpers: `Q(str)→CleaningProgressMetadata` (1451), `M(metadata)→bool`
(1351), `R(str)→Map` (1706, snapshot decode), `x0(map)→String` (9178,
snapshot encode), `y0(str)→Object` (9369).

## Cleaning progress — `v0` (`syncCleaningProgressFromDp`, 38065-39429)

Invoked at the tail of `D0` with the **incoming normalized map** (the
post-`applyToMap` map, not the merged cache):

1. `status = Dp101RunModeSet.runningStatusFromDpStates(map)`;
   `spread = Dp102SystemSettings.spreadCountFromDpStates(map, 0)`
   (`__dp102_setting_smooth__` Number → `102` → default).
   `expected = spread == 7 ? 205 : spread * 25 + 80`.
2. `meta = x[devId] ?: EMPTY`; `now = currentTimeMillis()`.
3. `clean_start`:
   - `meta.isCompleted()` → reset: `EMPTY.copy(startedAt=now, expected,
     lastUpdatedAt=now)`, log, `l0(devId, now)` (persist start time).
   - else if `lastUpdatedAt > 0 && now - lastUpdatedAt < 3000` → recently
     updated: skip recalc; if `expected` differs, `copy$default` mask `0x6f`
     updates **only** `expectedDurationSeconds` (`lastUpdatedAt` preserved).
   - else recompute: `started = startedAt ?: now`;
     `elapsed = (now-started)/1000f + (stored > 0 ? stored : 0)`;
     `progress = coerceIn(elapsed/expected*100, 0, 100)` (Java float rules —
     `/0` → ±Inf/NaN, NaN survives `coerceIn`);
     `copy(startedAt, lastPausedAt=null, elapsed=stored (unchanged),
     progress, expected, completedAt=null, lastUpdatedAt=now)`;
     `r.containsKey(devId) == false` → `l0(devId, started)`.
4. `clean_pause`: `elapsed = (now-started)/1000f + stored` (unconditional add);
   `copy(startedAt=null, lastPausedAt=now, elapsed, progress, expected,
   completedAt=null, lastUpdatedAt=now)` — **startedAt is cleared** on pause;
   `isPaused()` = `startedAt==null && lastPausedAt!=null && completedAt==null`.
5. done — `status ∈ {manual_clean_completed, scheduled_clean_completed,
   auttomatic_clean_completed, device_power_on}` → `e0(devId)` (remove
   `cleaning_start_time_` key) then `c0(devId)`; no `q0` call.
6. other status: if `expected` differs → `copy$default` mask `0x2f` updates
   `expectedDurationSeconds` **and** `lastUpdatedAt=now`.
7. `areEqual(new, meta)` false → `q0(devId, new, persist=true)`.

`q0` (34184-34460): `M(meta)` empty → `x.remove`/`r.remove`/`B.remove` +
`s`/`y`/`C` flow updates; else `x[devId]=meta`, `r` mirrored from
`startedAt` (null → remove), `B` mirrored from `elapsedBeforePauseSeconds`
(`<= 0` → remove). `persist` → `M(meta)` ? `d0` : `k0`.

`c0` (`removeCleaningProgressState`, 23697): `x.remove` + `y` flow + `d0`
only — **`r`/`B` keep stale entries** (faithful quirk).

`M` (1351): empty iff `startedAt==null && lastPausedAt==null &&
elapsed<=0 && progress<=0 && expected==0 && completedAt==null`
(`lastUpdatedAt` not checked; `cmpg`/`cmpl` make NaN floats non-empty).

`k0` (30353): `JSONObject` with skipped-null `startedAt`/`lastPausedAt`/
`completedAt`, always-present `elapsedBeforePauseSeconds`/`progressPercent`
/`expectedDurationSeconds`/`lastUpdatedAt`; stored under
`cleaning_progress_state_<devId>`.

Port: `app/repository.py` — `CleaningProgressMetadata`,
`EMPTY_CLEANING_PROGRESS`, `sync_cleaning_progress_from_dp` (`v0`),
`update_cleaning_progress` (`q0`), `remove_cleaning_progress` (`c0`),
`save/remove_cleaning_start_time` (`l0`/`e0`),
`save_cleaning_progress_state` (`k0`),
`remove_cleaning_progress_state_from_datastore` (`d0`),
`cleaning_progress_to/from_json` (`k0` serializer / `Q`), `datastore` seam.

## DP merge semantics

`DeviceDpStateResolver` (util/DeviceDpStateResolver.smali, 687 lines) — see
earlier finding: in the cloud-vs-cached merge (`b`), ALL cloud dps entries
overwrite cached first (lines ~303-370), making the later precedence loop a
redundant re-copy; final DP-101 normalization via `Dp101RunModeSet`.
`TuyaDeviceBeanDpsReader` (629 lines) reads DeviceBean.dps.

## Send post-write hook

`DeviceRepository.P(devId, dps, cont)` (17172-17554) — invoked after
`sendDeviceCommand` success (Helper.I step 3). Decoded in Phase 0f:
filters the sent dps down to the "critical DP" set, then delegates to
`D0` (`updateDeviceDps`) which merges into the cached device dps and
writes the `device_dp_snapshot_<devId>` DataStore snapshot — the
optimistic local update path. Full critical-DP set and merge order:
`09-dp-model.md`.

## TBD

- Which DeviceRepository methods correspond to public API names (Kotlin
  metadata is stripped; infer from inner-class names like
  `loadDevicesFromTuyaSDK$1`, `syncDeviceDpFromCloud$1`, `updateDeviceDps$1`,
  `ensureHomeInitialized$1`, `getHomeDetailAndDevices$1`,
  `refreshDevicesForHome$1`, `extractDevicesFromHomeDetail$*`).
- `extractDevicesFromHomeDetail` variants 1-4 (filtering rules).
- Order/keys of `device_list_order` (sort key: `sortedDevices$2`).
