# 09 — DP model: constants, packed codecs, state resolution

Popur DP model classes live in `smali/com/popur/android/core/model/data/`
(non-obfuscated Kotlin). They are the canonical vocabulary + wire codecs for
the S7/X5 DP set. All packed payloads are delivered as **raw hex strings** (or
occasionally `byte[]`/JSON-int-array) inside the `dps` map.

## `DeviceDpConstants` (DeviceDpConstants.smali:386-1030)

Static `String` fields naming every DP id the app knows. **Same DP id is
reused across product variants** — e.g. `101` is BATTERY_LEVEL /
DEVICE_STATUS / HUMIDITY / MACHINE_STATUS / TEMPERATURE depending on model;
the app selects by product/category. Full table:

```
1   clean_control / pause / recent-activity-code (variant)
3   start_self_check            5   no_troll_delay / mode_cooling
6   cat_weight                  7   cleaning_stats / daily_clean_count
8   clean_duration              9   manual_clean
10  bin_full_detection / do_not_disturb_raw
12  auto_clean_count            13  bin_full_disable
14  scheduled_clean/enable/time 15  scheduled_clean_count
17  pet_weight_tracking         18  auto_clean_countdown/interval
19  manual_clean_count          20  switch_led
21  notification / voice_prompt / work_mode
22  bright_value / fault_alarm / fault_code / machine_control_status /
    recent_activity_status
23  device_reset / factory_reset
24  running_status
31  switch / trash_bin_control
101 device/battery/machine status (packed report — see below)
102 cleaning_intensity / operation_mode / system_settings (packed —
    see below)
103 cycle_count_type / display_type / time_power_on_off (packed)
104 dustbin_settings (packed)   105 button_lock / key_settings (packed)
106 self_check_status (packed)  107 special_operate / spin_control
108 sifter_control              109 bin_full_level / machine_work_mode
110 device_identity / self_check_start
111 self_check_progress / sensor_calibration / start_weight_calibration
112 radar_range / notify_all    113 delay_clean_time / notify_pet_detected
114 notify_pet_done_business    115 notify_pet_left
116 total_use_time              117 auto_bury_time / notify_clean_started
118 bin_product_info / notify_clean_paused
119 dog_proof_time / notify_clean_resumed
120 sifter_spec / notify_automatic_clean
121 litter_capacity / notify_schedule_clean
122 bin_status(-report) / notify_manual_clean
123 chunky_litter_level / notify_bin_full
124 mode_no_troll_switch / notify_self_check_done
125 self_check_fault (bitmap)   126 cat_presence
127 mode_chunky_litter_switch   128 mode_special_clean / soft_stool_mode
129 mode_soft_stool_switch      130 radar_sensitivity
131 mode_auto_bury_switch       132 mode_dog_proof_switch
133 utc_setting                 134 device_rename
135 device_notification_switch / scheduled_power
136 bin_force_use               137 mode_parkour / mode_zoomie
138 mode_care                   139 anti_interference
140 device_lock                 141 mode_sentinel
143 start_weight_calibration_legacy
144 mode_linger_switch / sifter_status
145 bin_overload_use            146 clean_count_after_full
147 notification_pet_detected   148 mode_linger / notification_pet_finished
149 notification_cleaning_started
150 fault_free_time / filter_life
151 notification_automatic_cleaning
152 clean_count / total_clean_count
153 mode_chase / notification_manual_cleaning
154 cat_toilet_time             155 notification_scheduled_cleaning
156 notification_bin_full       157 notification_self_check
159 keep_upright
```

Synthetic app-internal key: `"__dp102_setting_smooth__"` — mirrors DP-102
byte 14 (litter spread count) so the UI can write it as a standalone DP
(DeviceDpConstants.smali:640).

### Inner enums (DeviceDpConstants$*.smali)

- `WorkMode`: AUTO/SCHEDULED/SMART = `"auto_clean"`, MANUAL =
  `"manual_clean"`, plus COLOUR/MUSIC/SCENE/WHITE (non-S7 legacy).
- `OperationMode`: `"auto_clean"`, `"manual_clean"`, `"forbidden_clean"`.
- `DeviceStatus` (int): STANDBY=0, WORKING=1, PAUSED=2, FAULT=3, CHARGING=4,
  SLEEPING=5.
- `CatPresence`: `"no_cat"`, `"cat_exist"`, `"cat_left"`,
  `"cat_done_business"`.
- `SifterControl`: `"open"`, `"close"`, `"start_scoop"`, `"pause_scoop"`.
- `BinStatus` (int): EMPTY=0, NEARLY_EMPTY=1, HALF_FULL=2, NEARLY_FULL=3,
  FULL=4, NEED_EMPTY=5.
- `DisplayType`: `"cycles_today"`, `"cycles_bin_full"`,
  `"leftime_cycles"` (sic).
- `SifterSpec`: `"size_6mm"`, `"size_8mm"`, `"size_10mm"`.
- `LitterCapacity`: `"litter_depleted"`, `"litter_normal"`,
  `"litter_middle"`, `"litter_full"`, `"litter_too_much"`.

## Universal `decodeToBytes` coercion

Defined on `Dp102SystemSettings.decodeToBytes` (Dp102SystemSettings.smali:
2061-2400) and re-used by the other codecs (`Dp101RunModeSet.decodeToBytes`
delegates straight to it, Dp101RunModeSet.smali:526-543). `Dp103`/`Dp105`
have identical private copies:

| Input | Result |
|---|---|
| `null` | `null` |
| `byte[]` | passthrough |
| `String` | try JSON-int-array `"[1, 2, …]"` first; else hex-string decode |
| `CharSequence` | `toString()` → recurse |
| `Collection` | each `Number` → `int` → `byte`; non-numbers skipped; empty → `null` |
| other | `null` |

Hex decode (`decodeHexStringToBytesOrNull`, Dp102SystemSettings.smali:
389-643): strip all whitespace (`\s+` → `""`), lowercase, parse pairs as
radix-16; malformed → `null`.

`encodeToHex` (e.g. Dp102SystemSettings.smali:3058): per-byte
`String.format("%02x")` — lowercase hex.

`normalizeBytes`/`normalizePayload` (Dp102SystemSettings.smali:1093):
`null`/empty → `new byte[TOTAL]`; len ≥ TOTAL → `copyOf(TOTAL)`; len <
TOTAL → zero-pad to TOTAL.

## DP 101 — packed run-mode report (`Dp101RunModeSet`, 3568 lines)

`ParsedReport{binStatus, runningStatus, machineStatus, catPresence,
countdownMinutes}` — a **5-byte** report.

Enum tables (`<clinit>` 201-462 — order = wire index):

```
binStatusValues    = [unfound, near_empty, half_empty, almost_full,
                      bin_full, bin_opned]          # sic "bin_opned"
runningStatusValues= [idle, clean_start, clean_pause, manual_clean_completed,
                      scheduled_clean_completed, auttomatic_clean_completed]
                                                    # sic "auttomatic"
machineStatusValues= [power_on, hibernating, disturb_mode, power_off]
catPresenceValues  = [no_cat, cat_exist, cat_left, cat_done_business]
legacyNormalizedKeys = {"24", "18"}
PENDING_CLEANING_ACTIONS = {start_cleaning, continue_cleaning,
                            pause_cleaning}
```

`parse(Object)` (2766-3128):

1. If value is a String **contained in `machineStatusValues`** → return
   `DEFAULT.copy(machineStatus=value)` (legacy plain-enum form).
2. Else `decodeToBytes` → `null` or len < 5 → `null`.
3. `b[0]&0xff` → `binStatusValues[i]` (out-of-range → `"near_empty"`);
   `b[1]` → runningStatus (default `"idle"`); `b[2]` → machineStatus
   (default `"power_on"`); `b[3]` → catPresence (default `"no_cat"`);
   `b[4]` → `countdownMinutes` unsigned.

`encodeReport` (1431-1621): 5 bytes `[idx(bin), idx(running),
idx(machine), idx(cat), coerce(countdown,0,255)]`; `indexOf` falls back to
**1** for binStatus, **0** for the others (1463-1466 vs `indexOf$default`
flag 0x4).

`applyToMap(dpsData)` (1013-1093) — the merge applied to every inbound/
outbound dp map:

1. `migrateLegacyKeys(map)` — folds legacy keys {24, 18} into the report.
2. `parse(map["101"])`:
   - `null` → `stripLegacyKeys`, `remove("122")`, return.
   - If raw `101` did not decode to bytes (plain enum string) →
     `map["101"] = encodeReport(parsed)` — rewrites to canonical bytes.
3. `applyDerivedFields`: `map["126"] = parsed.catPresence` (491-524).
4. `stripLegacyKeys` + `remove("122")`.
5. `reconcileCleanControl` (762-960): `cleanControlFromDpStates` reads DP
   `"1"` as Boolean (accepts Boolean or `"true"`/`"false"` strings,
   1199-1377). If non-null: writes `map["1"]=bool` back, then — `true`
   && runningStatus==`clean_pause` → `clean_start`; `false` &&
   runningStatus==`clean_start` → `clean_pause`; else untouched. If a
   change: `map["101"] = encodeReport(updated)` + re-apply derived 126.

`patchDpStates(dps, runningStatus?, machineStatus?, countdown?,
binStatus?, catPresence?)` (3203-3436): parse current (or DEFAULT), copy
with non-null overrides, `map["101"]=encodeReport`, stripLegacyKeys,
applyDerivedFields. Returns the new mutable map.

`ParsedReport.DEFAULT` = `(near_empty, idle, power_on, no_cat, 0)`
(ParsedReport.smali:106-163).

`migrateLegacyKeys(map)` (2287-2764) — legacy → packed-101 fold:

- `map["101"]` decodable to bytes → `stripLegacyKeys`, return.
- Else gather: `runningStatus = map["24"] as String`,
  `machineStatus = map["101"] as String` (kept only if ∈
  `machineStatusValues`), `countdown = map["18"] as Integer`.
- If runningStatus==null && machineStatus invalid && countdown==null →
  `stripLegacyKeys`, return.
- binStatus = `map["122"]` as String or `DEFAULT.binStatus`;
  catPresence = `map["126"]` as String or `DEFAULT.catPresence`;
  remaining fields default from `DEFAULT`.
- `map["101"] = encodeReport(ParsedReport(...))` → `stripLegacyKeys`.

`stripLegacyKeys` removes `"24"` and `"18"` (legacyNormalizedKeys).

`mergeDuringPendingCleaningAction(incoming, snapshot, pendingAction,
expectedRunningStatus)` (1814-2285) — optimistic-UI protection:

- incoming empty OR `pendingAction ∉ PENDING_CLEANING_ACTIONS` →
  return incoming.
- incoming runningStatus == expectedRunningStatus → return incoming
  (action settled).
- expected==`clean_start` && incoming runningStatus==`clean_pause` →
  return incoming.
- Else patch: `patchDpStates(incoming, runningStatus=expected,
  machineStatus=snapshot.machineStatus, countdown=(0 if
  pendingAction=="continue_cleaning" else snapshot.countdown),
  binStatus=snapshot.binStatus, catPresence=snapshot.catPresence)`;
  then `map["1"] = (start_cleaning|continue_cleaning → true,
  pause_cleaning → false, else snapshot clean-control)`;
  then `applyToMap` and return.

Read helpers: `binStatusFromDpStates`, `catPresenceFromDpStates`,
`cleanControlFromDpStates`, `countdownMinutesFromDpStates`,
`runningStatusFromDpStates` — all `parseFromDpStates` (reads `map["101"]`)
then field access.

## DP 102 — packed system settings (`Dp102SystemSettings`, 5100 lines)

29-byte (`TOTAL_BYTES=0x1d`) bit-field blob. Byte layout (fields 236-302):

| Idx | Field | Encoding |
|---|---|---|
| 10 (0xA) | ACTIVE_SHIELD_SENSITIVE | int |
| 11 (0xB) | ACTIVE_SHIELD_RANGE | int |
| 12 (0xC) | ACTIVE_SHIELD_ANTI | toggle |
| 13 (0xD) | SETTING_DELAY | minutes, clamp 1-60, default 5 |
| 14 (0xE) | SETTING_SMOOTH | spread count, clamp 2-7, default 3 |
| 15 (0xF) | SETTING_TIMEZONE | signed byte, clamp -12..12 |
| 17 (0x11) | DEVICE_COLOR | 0=white, 1=black |
| 18 (0x12) | DETAILED_NOTIFICATION | bitmask (below) |
| 19 (0x13) | NOTIFICATION_MASTER | toggle (deprecated — see DpNotificationSettings) |
| 20 (0x14) | STATUS_LIGHT | toggle |
| 21 (0x15) | BUZZER | toggle |
| 22 (0x16) | WEIGHT_FUNCTION | bitmask (below) |
| 23 (0x17) | EXPERT_MODE | toggle |
| 24 (0x18) | AUTO_POWER_CYCLE | toggle |
| 25 (0x19) | LOWER_SPEED | toggle |
| 26 (0x1A) | RESHUFFLE_CLUMPS | bit7 = reshuffle switch (0x80); low bits = oscillation index → `RESHUFFLE_OSCILLATION_LABELS` |
| 27 (0x1B) | DETAILED_NOTIFICATION_EXT | bitmask (below) |
| 28 (0x1C) | AUTO_SELF_CHECK | toggle |

`DETAILED_NOTIFICATION` bits (fields 192-214):
`NEW_FIRMWARE=0x01, BIN_FULL=0x02, CLEANING_PAUSED=0x04,
CLEANING_RESUMED=0x08, AUTOMATIC_CLEAN_COMPLETED=0x10,
CLEANING_STARTED=0x20, PET_FINISHED=0x40, PET_DETECTED=0x80`.

`DETAILED_NOTIFICATION_EXT` bits: `SELF_CHECK_COMPLETED=0x01,
PET_LEFT_WITHOUT=0x02, MANUAL_CLEAN_COMPLETED=0x04,
SCHEDULED_CLEAN_COMPLETED=0x08`.

`WEIGHT_FUNCTION` bits: `AUTOMATIC=0x01, SENTINEL=0x02, CARING=0x04,
TRACK_PET=0x40`.

Read pattern (`xxxFromDpStates`): `map["102"]` → `parseX` →
`decodeToBytes`/`normalizeBytes` → byte at idx → clamp via
`validateX` (ranges above) → or return caller default.
`readToggle(bytes, idx, def)`: `idx >= len` → `def`; else `byte != 0`
(1172-1212).

`spreadCountFromDpStates` special case (4597-4712): checks synthetic key
`__dp102_setting_smooth__` **first** (Number → int), then falls back to
byte 14 of `102`.

Write pattern (`bytesWithX(value, …)`): `decodeToBytes` →
`normalizeBytes(29)` → mutate byte(s) → caller `encodeToHex`s back into
`map["102"]`. E.g. `bytesWithSmoothSpread` (1822), `bytesWithTimezone`
(1870), `bytesWithToggle` (1918), `bytesWithNotificationBit`/`Ext`
(1522/1450), `bytesWithWeightFunctionBit` (1951), `bytesWithReshuffle*`
(1637/1725), `bytesWithDeviceColor` (1475).

`parse*` variants accept either the packed `102` value **or** a bare
Number (then just validate) — e.g. `parseDelayMinutes` (3599),
`parseSmoothSpreadCount` (4020), `parseTimezoneOffset` (4091).

## DP 103 — time power on/off (`Dp103TimePowerOnOff`, 3316 lines)

10-byte payload; `defaultPayload()` = 10 zero bytes (1293); normalize =
truncate/pad to 10 (1944).

| Idx | Field |
|---|---|
| 0 | power_on switch (≠0) |
| 1 | power_on repeat mask (day-of-week bitmask) |
| 2 | power_on hour (0-23) |
| 3 | power_on minute (0-59) |
| 4 | power_off switch |
| 5 | power_off repeat mask |
| 6 | power_off hour |
| 7 | power_off minute |
| 8 | hibernate_start (bool) |
| 9 | hibernate_duration minutes (coerce 0-255) |

`parsePayload`/`toBytes` read/write `TimerSlice`s via
`readTimerSlice(bytes, switchIdx, repeatIdx, hourIdx, minuteIdx)`
(2368-2490, 2893-3027). `withPowerOn`/`withPowerOff`/
`withHibernateStart`/`withHibernateDuration` mutate normalized copies.
`maskToRecurrenceText`/`recurrenceTextToMask` map the day mask to UI
text; `parseAmPmTime`/`formatAmPm` handle 12h display.

## DP 104 — dustbin settings (`Dp104DustbinSettings`, 1557 lines)

3-byte payload (TOTAL=3): `[0]` switches bitmask, `[1]` sensor
calibration, `[2]` cycle counts (fields 87-122).

Switch bits: `BIN_FULL_DETECTION=0x01, ALLOW_OVERFILL=0x02,
KEEP_UPRIGHT=0x04, DUMP_OVERRIDE=0x08, BLOCK_ON_FULL=0x10`;
`DEFAULT_SWITCHES_MASK=0x05`.

Calibration: level 0-3 (default 1) ↔ labels `Precise/Balanced/Extended/
Maximum` ↔ percents `25/50/75/100` (692-791).

Cycle counts: clamp 1-10, default 5.

## DP 105 — key/button settings (`Dp105KeySettings`, 1564 lines)

7-byte payload (TOTAL=7; fields 71-100):

| Idx | Field |
|---|---|
| 0 | LOCK bitmask — bit0..3 = key1..4; `LOCK_ALL_MASK=0x0f` |
| 1 | PRESS_SWITCH |
| 2 | PRESS_FUNC |
| 3 | HOLD_3S_SWITCH |
| 4 | HOLD_3S_FUNC |
| 5 | HOLD_7S_SWITCH |
| 6 | HOLD_7S_FUNC |

`isKeyLocked(bytes, keyIdx)` = `lock byte & (1<<keyIdx)`;
`withKeyLock`/`withAllKeysLocked` write bits; `defaultPayload` = 7 zeros.

## DP 106 — self-check status (`Dp106SelfCheckStatus`, 525 lines)

5-byte payload; byte 0 = progress percent (parse clamps to `Int` — usage
site caps display at 0-100; `const/16 0x64` at 440).

## DP 125 — self-check fault bitmap (`Dp125SelfCheckFault`, 590 lines)

`parseFaultValue(Object)` → `Long` bitmap (accepts Number/String);
`parseFaultItems(bits)` → list of fault entries, bit index → letter
(`0x41`='A' .. `0x5a`='Z' = 26 faults, 97-139). Fault detail URL template:
`https://popur.com/pages/s7-error-code-<letter>` (233); fallback label
`"Error code "` (199). `faultFromDpStates` reads `map["125"]` (316-332).

## DP 22 — recent activity status (`Dp22RecentActivityStatus`, 930 lines)

`parseStatusCode(String)` (612-799): trim → empty→null; `toIntOrNull` →
int code; lowercase; `0x`-prefix → hex int; else `NAME_TO_CODE` lookup:

```
idle=0  cat_exist=1  cat_left=2  cat_done_business=3
manual_clean_completed=4  scheduled_clean_completed=5
automatic_clean_completed=6  auttomatic_clean_completed=6   (sic)
bin_full=7  bin_ful=7                                       (sic)
"self-check completed"=8  self_check_completed=8
cleaning_started=9  clean_start=9
cleaning_paused=10  cleanning_paused=10                     (sic)
cleaning_resume=11  cleaning_resumed=11
```

`toActivityDisplayText` (801-930): 0→null, 1 "Pet detected",
2 "Pet left without business", 3 "Pet finished the business",
4 "Manual cleaning completed", 5 "Scheduled cleaning completed",
6 "Automatic cleaning completed", 7 "Bin full", 8 "Self-check completed",
9 "Cleaning started", 10 "Cleaning paused", 11 "Cleaning resumed";
>11 → null.

## Notification DPs (`DpNotificationSettings`, 644 lines)

Per-notification bool DPs `112..124` (no 116): `ALL_DP_IDS` =
[112,113,114,115,117,118,119,120,121,122,123,124] (91-135):

```
112 notify_all (master)        113 pet_detected     114 pet_done_business
115 pet_left                   117 clean_started    118 clean_paused
119 clean_resumed              120 automatic_clean  121 schedule_clean
122 manual_clean               123 bin_full         124 self_check_done
```

`fromDpStates(map)` builds `Settings` reading each id via `parseBool`
(485+) — accepts Boolean or `"true"`/`"false"` strings; missing →
default (true at 632 context).

## DeviceRepository post-command write (`P` / `D0`)

`DeviceRepository.P(devId, dps, cont)` (DeviceRepository.smali,
`updateDeviceDps` pipeline): returns early on empty map; filters `dps` to
the **critical-DP set**

```
{"125","101","1","126","102","__dp102_setting_smooth__","106","110"}
```

compares each kept value against current state, logs
`✅ 强制更新关键DP <id>: <old> -> <new>` on change, then calls
`D0(devId, filtered, cont)` — confirmed `D0` = `updateDeviceDps` (inner
class `DeviceRepository$updateDeviceDps$1`, ~12304+): the real DP-merge +
snapshot-persist path (`device_dp_snapshot_<devId>`).

## Open items

- `Dp102` `panelTogglesFromDpStates` field→toggle mapping (3251+) and
  `spinSettingsFromDpStates` (4415+) composite sub-structs — decode at
  implementation time against these IDX constants.
- `RESHUFFLE_OSCILLATION_LABELS` list contents (3124) — same.
- `DeviceRepository.D0`/`updateDeviceDps` full merge ordering vs
  `DeviceDpStateResolver` precedence (see `07-app-state.md`) — verify
  snapshot write order when implementing repository.
