# Popur S7 firmware-4 / app-v2 protocol map

See [`datapoints.md`](datapoints.md) for the complete live 40-point App-2 product inventory and
the observed 23-point LAN subset.

## Evidence and scope

This map comes from static analysis of the official `Popur-S7-v2.0.0.apk` used for app-v2. The
analyzed artifact has SHA-256:

`326e6586c07f68bd86955a5f5553c6736b709e124f4d4eb663aac82e6074361b`

The dedicated model classes in `com.popur.android.core.model.data` are the source of truth for
the packed formats implemented here:

- `Dp101RunModeSet`
- `Dp102SystemSettings`
- `Dp103TimePowerOnOff`
- `Dp104DustbinSettings`
- `Dp105KeySettings`
- `Dp106SelfCheckStatus`
- `Dp125SelfCheckFault`
- `Dp22RecentActivityStatus`
- `DpNotificationSettings`

The app contains a large `DeviceDpConstants` class with old symbolic names that collide on numeric
IDs. Those names document protocol history, but they do not make each alias a separate wire field.
This library uses the dedicated app-v2 model class when one exists and keeps the numeric ID as the
wire identity. `pypopur.reference` contains all **127** recovered symbolic aliases spanning **79**
distinct constant values. It tags each alias as current packed/scalar/action/notification,
DP102-subfield, or legacy/ambiguous; collisions remain visible through `DP_VALUE_ALIASES` instead
of being silently overwritten in a dictionary. `DP_VALUE_STATUS` separately records the app-v2
wire interpretation, which matters for values such as DP101 where the dedicated packed model is
current even though every old symbolic alias attached to `"101"` is stale or ambiguous.

## Packed DPs

### DP101 — run-mode report, 5 bytes

| Byte | Meaning | Encoding |
| ---: | --- | --- |
| 0 | Bin status | index into `unfound`, `near_empty`, `half_empty`, `almost_full`, `bin_full`, `bin_opned` |
| 1 | Running status | index into `idle`, `clean_start`, `clean_pause`, `manual_clean_completed`, `scheduled_clean_completed`, `auttomatic_clean_completed` |
| 2 | Machine status | index into `power_on`, `hibernating`, `disturb_mode`, `power_off` |
| 3 | Cat presence | index into `no_cat`, `cat_exist`, `cat_left`, `cat_done_business` |
| 4 | Cleaning countdown | unsigned 0…255 |

The misspellings `bin_opned` and `auttomatic_clean_completed` are present in the official app and
are preserved as wire enum values.

### DP102 — system settings, 29 bytes

Bytes not listed below have no recovered app-v2 semantic and are preserved during re-encoding.

| Byte | Meaning | Range / bits |
| ---: | --- | --- |
| 10 | Active-shield sensitivity | 1…10, app fallback 5 |
| 11 | Active-shield range | 1…5, app fallback 3 |
| 12 | Active-shield anti-interference | nonzero = enabled |
| 13 | Setting delay | 1…60 minutes, app fallback 5 |
| 14 | Smooth/litter spread count | clamped 2…7 |
| 15 | Timezone offset | signed byte, clamped -12…+12 |
| 17 | Device color | 0 white, 1 black |
| 18 | Legacy packed notification bits | `01` self-check, `02` bin full, `04` manual clean, `08` scheduled clean, `10` automatic clean, `20` cleaning started, `40` pet finished, `80` pet detected |
| 19 | Legacy notification master | nonzero = enabled |
| 20 | Status light | nonzero = enabled |
| 21 | Buzzer | nonzero = enabled |
| 22 | Weight functions | `01` automatic, `02` sentinel, `04` caring, `40` track pet data; unknown bits preserved |
| 23 | Pro/expert commands | nonzero = enabled |
| 24 | Automatic power cycle | nonzero = enabled |
| 25 | Lower speed | nonzero = enabled |
| 26 | Reshuffle | `80` enable bit; low 7 bits index `2X`, `3X`, `4X`, `5X` |
| 27 | Legacy extended notifications | `01` new firmware, `02` pet left without business, `04` cleaning paused, `08` cleaning resumed |
| 28 | Automatic self-check | nonzero = enabled |

The app marks the notification fields inside DP102 deprecated in favor of the standalone
notification DPs below. They remain decoded because firmware state may still contain them.

### DP103 — power timers / hibernate, 10 bytes

| Bytes | Meaning |
| --- | --- |
| 0,1,2,3 | power-on enabled, repeat mask, hour, minute |
| 4,5,6,7 | power-off enabled, repeat mask, hour, minute |
| 8 | hibernate-start boolean |
| 9 | hibernate duration, unsigned 0…255 minutes |

Hours are clamped to 0…23 and minutes to 0…59 on encode. The 7-bit recurrence mask is Monday
through Sunday as bits `01,02,04,08,10,20,40`; zero means once and `0x7f` means every day.

### DP104 — dustbin settings, 3 bytes

| Byte | Meaning | Encoding |
| ---: | --- | --- |
| 0 | Dustbin toggle mask | `01` bin-full detection, `02` allow overfill, `04` keep upright, `08` dump override, `10` block on full |
| 1 | Sensor calibration | 0 precise (25%), 1 balanced (50%), 2 extended (75%), 3 maximum (100%) |
| 2 | Cycle count | 1…10, default 5 |

The app's default raw value is `05 01 05`.

### DP105 — key settings, 7 bytes

| Byte | Meaning |
| ---: | --- |
| 0 | lock mask for keys 1…4 (`01,02,04,08`) |
| 1 | short-press switch |
| 2 | short-press function code |
| 3 | 3-second hold switch |
| 4 | 3-second hold function code |
| 5 | 7-second hold switch |
| 6 | 7-second hold function code |

The app's complete default payload is `00 01 00 01 02 01 03`. An undersized DP105 payload is
replaced with that complete default rather than partially padded.

### DP106 — self-check status, 5 bytes

Byte 0 is self-check progress, clamped to 0…100 by the app. Bytes 1…4 have no recovered semantic
in this model and are retained when re-encoding.

### DP125 — self-check fault bitmask

DP125 is a scalar bitmask rather than a byte-array payload. Bits 0…25 map to error codes A…Z.
The app constructs documentation URLs as `https://popur.com/pages/s7-error-code-<letter>`.
Numeric values are accepted directly. For string values the app attempts hexadecimal parsing
first, so the string `"10"` means `0x10`, not decimal 10; `pypopur` mirrors that behavior.

## DP22 — recent activity

DP22 is parsed as a scalar status code with these recovered values:

| Code | Activity |
| ---: | --- |
| 0 | idle/no display event |
| 1 | pet detected |
| 2 | pet left without business |
| 3 | pet finished business |
| 4 | manual cleaning completed |
| 5 | scheduled cleaning completed |
| 6 | automatic cleaning completed |
| 7 | bin full |
| 8 | self-check completed |
| 9 | cleaning started |
| 10 | cleaning paused |
| 11 | cleaning resumed |

The parser also accepts the app's textual aliases and typos (`auttomatic_clean_completed`,
`bin_ful`, `cleanning_paused`, and others).

## Standalone notification DPs

`DpNotificationSettings` supersedes DP102's old packed notification bytes. Each value is a
boolean-like scalar:

| DP | Meaning |
| ---: | --- |
| 112 | notification master |
| 113 | pet detected |
| 114 | pet finished business |
| 115 | pet left without business |
| 117 | cleaning started |
| 118 | cleaning paused |
| 119 | cleaning resumed |
| 120 | automatic cleaning completed |
| 121 | scheduled cleaning completed |
| 122 | manual cleaning completed |
| 123 | bin full |
| 124 | self-check completed |

This is one example of why old names in `DeviceDpConstants` cannot be treated as independent
current DPs: historical constants assign other meanings to some of the same numbers.

## Other app-v2 datapoints

The current S7 control screens use DP1 for cleaning control/pause, DP31 for the dustbin door,
DP107 for service operations, DP108 for sifter control, DP109 for power/reboot, DP110 for
self-check start/stop, and DP111 for scale recalibration. Recovered command values are:

| DP | App operation | Wire value |
| ---: | --- | --- |
| 31 | open/close dustbin | boolean |
| 107 | zero dustbin counter | `zeoring` (firmware spelling) |
| 107 | recalibrate spin sensor | `specail_calibrate` (firmware spelling) |
| 108 | sifter | `open`, `close`, `start_scoop`, `pause_scoop` |
| 109 | machine power | `power_on`, `power_off`, `reboot` |
| 110 | self-check | boolean |
| 111 | recalibrate scale | `true` |

DP3 is a legacy self-check alias in the generic constants table; the current S7 self-check screen
and the live product record use DP110. Other ordinary values include DP7 daily cleaning count,
DP8 clean duration, DP10 do-not-disturb schedule, DP12 automatic cleaning count, DP14 scheduled
clean, DP15 scheduled clean count, DP19 manual clean count, DP20 another raw schedule/settings
payload, DP22 recent activity, DP116 total use time, DP126 cat presence, DP146 clean count after a
full bin, DP150 fault-free use time, and DP152 lifetime clean count.

Several numbers have stale aliases elsewhere in the APK. `pypopur` exposes direct raw DPS access
where the current firmware-4 payload is not statically unambiguous. `DeviceSnapshot` decodes all
confirmed counters above while retaining the complete `raw_dps` mapping.

### Live product record versus LAN status

The authorized live S7's `thing.m.device.get` record declares 40 current datapoints:

`1, 7, 8, 10, 12, 14, 15, 19, 20, 22, 31, 101–126, 146, 150, 152`.

Ordinary authenticated Tuya 3.5 LAN status and explicit read-only UPDATEDPS requests consistently
return 23 of those points:

`1, 7, 8, 12, 22, 109, 110, 112–125, 146, 152`.

Within `112–125`, DP116 is total use time and DP125 is the self-check fault bitmask; the remaining
points are notification switches. The mobile record therefore supplies the packed DP101–106
settings and other cloud-cached values that this firmware omits from LAN status. `PopurAccount`
exposes these read-only values through `device_dps()` and `device_snapshot()`; padded and
unpadded Base64 RAW values are decoded before the normal firmware codecs run.

Additional static `ValueRange` evidence establishes that **DP154 cat toilet time is measured in
seconds**, with an allowed range of **0–10000 s**. `pypopur.reference.SCALAR_DP_METADATA` records
that as `unit="s"`, `minimum=0`, `maximum=10000`. No inspected APK declaration yet proves a unit
for DP8 clean duration or DP116 total use time, so both remain intentionally unitless in metadata.

## Transport and capability boundary

The official app initializes the ThingClips/Tuya SDK and its device control path calls
`publishDps`. The bundled SDK has LAN/MQTT/BLE routing and uses a per-device `DeviceBean.localKey`
for local protocol traffic. Popur-owned code does not expose a user-facing local key and does not
hardcode an S7 protocol version.

| Capability | LAN / bootstrap status | Popur/Thing account status |
| --- | --- | --- |
| Read normal device DPS | implemented; passive discovery, account-derived key, Tuya 3.5 handshake, and authenticated polling live validated | generic cloud DPS transport remains pluggable |
| Write normal device DPS | implemented from APK semantics; no live write was sent because the owner requested read-only testing | generic cloud DPS transport remains pluggable |
| DP101–106 packed decode/encode | implemented locally in Python | same codec usable by future backend |
| DP125 faults / DP22 activity | implemented locally in Python | same codec usable by future backend |
| Standalone notification DPs | implemented locally in Python | same model usable by future backend |
| Device discovery | passive S7-filtered TinyTuya discovery implemented | not required after bootstrap |
| Account login / `localKey` acquisition | `PopurAccount` resolves a discovered S7 to `LocalDeviceConfig` | App-2 mobile request/signing/login flow implemented and live validated with the bundled version-bound profile; callers should persist and reuse `install_id` so account alerts do not treat every login as a new phone |
| Pet profile/history | no recovered LAN API | cloud-only Thing pet-center APIs in the APK |
| Historical cloud records/statistics | no recovered LAN API | cloud APIs in the APK; backend absent |
| Firmware/cloud account management | no | backend absent |

`LocalTuyaTransport` uses TinyTuya for the LAN framing/encryption and moves its blocking calls to
worker threads. The bundled Thing SDK explicitly defines local protocol 3.3, 3.4, 3.5, and 3.5.1
paths. With no explicit version, pypopur probes 3.5, 3.4, then 3.3 using status reads. TinyTuya's
normal version setter represents those three directly; pypopur does not pretend its float version
API can express the SDK's distinct 3.5.1 branch.

A live read-only run on one real firmware-4 S7 observed its Tuya broadcast, matched its account
record, retrieved its local key, completed a protocol **3.5** handshake, and read local status.
No device identifier, address, or key is recorded here. This is direct evidence for 3.5 on that
unit, while the fallback probes avoid generalizing one observed device to every firmware-4 S7.
TinyTuya exposes the broadcast product identifier as `productKey`; it matched the official pairing
filter in the APK. That filter's non-unique product metadata is exposed as `S7_PRODUCT_IDS`; no live
device-specific identifiers are included in the library.

TinyTuya error 914 means “key or version”. `pypopur` therefore raises `HandshakeError`, a plain
`TransportError`, for that ambiguous rejection and deliberately does not convert it into
`AuthenticationError` or `InvalidLocalKey`. An integration must not trigger a credential reauth
flow solely from that error without other evidence.

## App-2 account bootstrap

The inspected app uses the Thing mobile-account stack rather than a Popur-specific REST login.
`pypopur.mobile` reproduces the statically verified request flow. The ordinary Popur entry point
uses a version-bound profile derived from the audited App 2.0.0 APK, while explicit-profile and
APK-derived constructors remain available:

1. request a one-use username token with `thing.m.user.username.token.get`;
2. MD5 the password to lowercase hexadecimal and RSA/PKCS#1-v1.5 encrypt that text with the
   token's decimal modulus/exponent;
3. authenticate with `thing.m.user.email.password.login`;
4. retain `sid`, `ecode`, account/domain metadata, and adopt `domain.mobileApiUrl` when returned;
5. enumerate homes/devices and obtain the matching S7's `localKey` from the account device record
   or `thing.m.device.key.get`;
6. return a `LocalDeviceConfig` so routine operation can move to the LAN transport.

The mobile transport also mirrors the inspected SDK's security envelope. The signer whitelists and
alphabetically sorts the same ATOP fields, substitutes the SDK's reordered MD5 of `postData`, and
HMAC-SHA256 signs the resulting `key=value||...` string. For `et=3`, `postData` is AES-128-GCM
encrypted using the SDK-compatible per-request key derivation, Base64 encoded, and the encrypted
body is what gets signed. The native security master material is supplied through
`MobileAppProfile`; object representations redact it. The bundled profile contains only OEM
material shipped in the public Popur APK, never user account, session, or device credentials.

Normal Popur App-2 email/password login is backed by the inspected APK and has been validated
against an authorized live account. No MFA branch is present in Popur App 2.0.0, so pypopur does
not expose one.

`CloudTransport.login()` still raises `UnsupportedCloudAuthentication`. That class is the generic
cloud DPS transport abstraction and is separate from the one-time mobile account bootstrap above;
it can wrap a future independently authenticated long-lived cloud backend without changing the LAN
client or codec model.
