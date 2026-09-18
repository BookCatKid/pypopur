# 12 — Module audit: existing pypopur vs the APK spec

Phase 1 verdicts. Every module was treated as suspect and compared against the
Phase-0 parity docs (`01`–`11`). Verdicts: **keep** (behavior matches spec or is
neutral), **fix** (right shape, wrong/incomplete semantics), **rewrite**
(fundamentally divergent or absent behavior).

## Summary table

| Module | Verdict | Basis |
|---|---|---|
| `exceptions.py` | keep | neutral error taxonomy |
| `transport.py` | keep | neutral client-facing seam; real dispatch lives underneath |
| `bootstrap.py` | keep | thin provider handoff |
| `popur_app2_material.py` | keep | constants verified vs APK (client id, chKey, master structure) |
| `reference.py` | keep | alias table shape verified; rows spot-checked vs `DeviceDpConstants` |
| `models.py` | done | enums/defaults verified vs smali (DP104, FAULT_ITEMS, reshuffle labels) |
| `codec.py` | done | `decode_raw_bytes` delegates to `decodeToBytes` port; `intValue()`/`toIntOrNull` exact |
| `dps.py` | done | all bit fields verified vs smali; DP109/DP126 semantics corrected |
| `client.py` | done | sits on `pipeline.py` comm-pipeline transport; command DPs verified |
| `discovery.py` | done | rewritten on `sdk/discovery.py` + real UDP socket stack |
| `local.py` | done | rewritten on real 0x55aa/session-key `sdk/lan_*` stack |
| `cloud.py` | done | `CloudChannelBackend`: MQTT-first / HTTP-fallback / 10203 |
| `mobile.py` | done | crypto/sign/login verified; batch bootstrap + retry/session/region added; typed read surface (`thing_model`, `device_events`, `firmware_info`, `device_meta`, `biz_props`, `device_timezone`, `timers`, `datapoint_stats`, `datapoint_stat_rank`, `pets`, `pet_records`, `timer_categories`, `timer_groups`, `auto_upgrade_switch`) + management writes (`rename_device`, `update_device`, `remove_device`, `confirm/cancel_firmware_upgrade`, `set_auto_upgrade`, timer group CRUD, `add/update/delete_pet`) + `connect_events` |
| `pipeline.py` | done | `PipelineTransport` composing LAN + cloud via `ThingDevicePresenter` |
| `events.py` | done | session→MQTT construction (`getMqttConfigInfo` token=sid, appTag="os"), `qqpqqpq` listener (topic suffixes, getLocalKey/isDataUpdated prefix strip), `CentralDpIngest` bridge |
| `reads.py` | done | typed beans for `dbppbbp` read endpoints (operate log, upgrade info, timezone, timers, biz props, datapoint stats) plus `m.ha.pet.group.list`/`record.list` pets (`Pet`, `PetRecord`) |
| `writes.py` | done | `petJson`/`queryJson` builders (`PetRemoteDataSource`), `TimerInstruction`/`instruct` — backs `PopurAccount` device mgmt (`thing.m.device.update` 1.3.1, `name.update`, `app.smart.local.device.remove`), OTA (`upgrade.confirm` 3.0/`cancel`/auto-switch), cloud timers (`bqbdpqd` add/update/remove/status/category), pet add/update/delete (`m.ha.pet.group.*`) |
| `__init__.py` | done | re-exports updated during rebuild |

## Per-module detail

### `popur_app2_material.py` — keep

`APP2_CLIENT_ID = "aup8mma84uvgeeeayman"`, `APP2_CH_KEY = "fa44caaa"`,
`APP2_NATIVE_MASTER_HEX` decodes to
`com.smartapp.popur.app_<certSha256 colon-hex>_<transformed component>_<appSecret>`
— matches the master structure in `02-security.md`.

### `codec.py` — done

`decode_raw_bytes` now delegates to `app.dp101.decode_to_bytes` — the
`Dp102SystemSettings.decodeToBytes` port (all Dp* classes delegate to that
singleton in smali). Verified semantics:

- `String` → `decodeJsonArrayStringToBytes` (trim → `[…]` → inner split
  on `,` → `toIntOrNull` per token, bad tokens **skipped not fatal**,
  empty result → null → hex fallback), then `decodeHexStringToBytesOrNull`
  (`\s+` stripped, empty→`byte[0]`, odd→null, chunked `parseInt(_,16)`).
- `Collection` → `instanceof Number` → `Number.intValue()` — float
  truncation toward zero, NaN→0, ±int32 saturation, int wrap; bools and
  non-Numbers skipped (ported as `_int_value`/`_to_int_or_null`).
- `[]`/`""` → `byte[0]`; `null` → null. `byte[]`/`CharSequence` paths
  match (CharSequence→toString covered by `str`).
- `allow_base64` remains a pypopur extension: the app does base64→hex at
  the transport boundary (`DevUtil.decodeRaw`), never in the DP codec.
- `normalize_bytes` = `normalizeBytes` — pads/truncates to the DP's fixed
  length (DP102 → 0x1d/29, verified).

### `models.py` — done

All previously unproven items verified against smali:

- `DP104_DEFAULT = (0x05, 0x01, 0x05)` — matches `Dp104DustbinSettings`.
- `FAULT_ITEMS` — `Dp125SelfCheckFault.<clinit>` iterates `'A'..'Z'`,
  `mask = 1L<<i`, label `"Error code "+ch`, url `s7-error-code-<lower>` —
  identical to the generated tuple.
- `DP102_RESHUFFLE_LABELS = ("2X","3X","4X","5X")` — matches
  `RESHUFFLE_OSCILLATION_LABELS` `listOf("2X","3X","4X","5X")`; index
  `& 0x7f`, unknown → `"2X"`, `toIndex` unknown → `0` (both ported).

### `dps.py` — done

All bit fields verified against `Dp102SystemSettings` smali:

- Notification byte 0x12: `0x01 selfCheck, 0x02 binFull, 0x04
  manualCleaning, 0x08 scheduledCleaning, 0x10 automaticCleaning, 0x20
  cleaningStarted, 0x40 petFinished, 0x80 petDetected` — componentN order
  confirmed. Ext byte 0x1b: `0x01 newFirmware, 0x02 petLeftWithoutBusiness,
  0x04 cleaningPaused, 0x08 cleaningResumed`. Weight byte 0x16: `0x01
  automatic, 0x02 sentinel, 0x04 caring, 0x40 trackPetData`.
- Panel toggles: `readToggle(b, 0x14, true)`, `(b, 0x15, true)`,
  `(b, 0x17, false)` — `b[i]!=0`, OOB→default (unreachable after
  normalizeBytes→29).
- Reshuffle byte 0x1a: `0x80` enable + low-7 label index — verified.
- `decode_dp109_machine_status` **removed** — the app never reads "109"
  as a scalar; `machineStatusFromDpStates` is DP101-only and
  `DeviceFunctionBarStateKt` falls back to the raw `"101"` value.
- `decode_dp126_cat_presence` restricted to String — matches the
  `DeviceFunctionBarStateKt` fallback (`"126"` scalar, `instanceof
  String` only).
- `detailedNotificationFromDpStates` is `@Deprecated` in smali — the
  current model is `DpNotificationSettings` (standalone DPs 112–124
  minus 116), already covered by `decode_notification_settings`.
- `Dp101RunModeSet.migrateLegacyKeys`/`stripLegacyKeys`/
  `reconcileCleanControl`/`patchDpStates` live in `app/dp101.py`.
- `DevUtil.checkSendCommond`/`checkReceiveCommond`/`encodeRaw`/
  `decodeRaw` live in `sdk/validation.py`.
- DP-102 writes use the `bytesWith*` granular mutators
  (`dp102_bytes_with_*`, ported from smali); `encode_dp102`'s
  read-modify-write diff is a convenience that produces identical output
  for field-setter callers.

### `reference.py` — done

All 126 `symbol → value` rows verified against `DeviceDpConstants` smali
— zero mismatches; the only extra row is the documented synthetic
`__dp102_setting_smooth__`. `S7_PRODUCT_IDS` verified against
`DevicePairingViewModel.<clinit>` (`setOf("takeu8kka3naw0rk",
"63mvaowa9snym978")`). `wire_status`/status classification is a
pypopur concept, fine to keep for callers but not part of app parity.

### `client.py` — done

- Command DPs verified against `UnifiedDeviceControlHelper` smali: DP1
  bool, DP108 sifter string, DP109 machine-control string, DP31 bin bool,
  DP110 self-check bool, DP111 weight-calibrate bool — all match.
- `PopurClient.pipeline()` returns `PipelineTransport` — the app's
  communication-modes chain-of-responsibility (LAN gate → watchdog →
  cloud MQTT/HTTP), post-command repository hook included.

### `discovery.py` — done

Rewritten on `sdk/discovery.py` + `SocketThingNetworkApi`: real UDP
6650/6667/7000 listeners, `fixed_key.bmp` announcement decrypt, gwMap
dedup/evict, drain-to-monitors, `qbdpdpp` onFind/addHgw routing + LAN
backoff. `discover_s7` integration-tested over real sockets.

### `local.py` — done

Rewritten on the `sdk/lan_*` stack: real 0x55aa socket transport
(`SocketThingNetworkApi`), session-key negotiation, lpv-versioned
`HRequest` assembly, STATUS/DP_QUERY decoders, `ThingLocalControlBean`
publish + `normalControl` query. End-to-end socket tests.

### `cloud.py` — done

`CloudChannelBackend` + `DeviceCommController.send` (the `qqdbbpp.send`
port): MQTT `publishDevice` when `isRealConnect`, `sendByHttp` fallback
when MQTT down but network up, `10203` when the device is offline.

### `mobile.py` — done

Verified against `02-security.md` / `03-http.md` / `06-auth.md` and the
native emulator (`popur-research/emu_jni.py`):

- `canonical_sign_input` (sorted `k=v||` whitelist, postData → md5 +
  4-block swap), `sign_mobile_params` (**HMAC-SHA256**
  `hmac_sha256(GLOBAL_S, canonical)` — verified by end-to-end cmd-1
  emulation; the earlier "nested MD5" note had emulated cmd 2's
  `hmacWrap` helper instead), `derive_request_key` (HMAC-SHA256 over
  master+`_ecode`, hex[:16] ASCII), `encrypt/decrypt_mobile_payload`
  (AES-128-GCM nonce-prepended — `decryptResponseData` verified
  end-to-end under emulation), `mobile_response_signature`
  (md5 `result=..||t=..||key`) — all match the decoded natives.
- Login: `thing.m.user.username.token.get` 2.0 → RSA-PKCS1v15(md5hex(pw))
  → `thing.m.user.email.password.login` 3.0 with literal
  `'{"group": 1}'` options + `ifencrypt: 1` — matches `06-auth.md`.
- Batch bootstrap: `thing.m.api.batch.invoke` v1.0 with the 8-API
  `ApiBean` composition (`zigbeeGroup: true`), `m.life.app.smart.local.
  device.list`, `m/ug` subscription — matches `08-bootstrap.md`.
- `device_dps` reads `dataPointInfo.dps` from `thing.m.device.get` —
  verified: `dataPointInfo` is a `DeviceRespBean` field, the same record
  the batch bootstrap populates.
- `TIME_VALIDATE_FAILED` single retry via `BusinessResponse.getTimestamp`
  resync, session-loss remap (105), `handleApiError` requeue policy, and
  `ApiUrlProvider` region routing — ported from `Business`.
- MQTT session in `sdk/mqtt_session.py` (`qpqbppd` OEM creds) + real wire
  client in `sdk/mqtt_client.py`; session→connection construction,
  `qqpqqpq` listener semantics and the `CentralDpIngest` bridge live in
  `events.py` (`PopurMqttEvents`, `DeviceEventListener`,
  `make_central_ingest_sink`), reachable via `PopurAccount.connect_events`.

## Architecture gaps (no module exists) — resolved

All five subsystems now exist:

1. **SDK core** — `sdk/device_cache.py` (`DeviceRespBean`, `ppqqqpb`
   cache, `pdppddb` ingest), `sdk/sando.py`, `sdk/dedup.py`.
2. **Comm pipeline** — `sdk/comm_pipeline.py` (9 handlers), `sdk/validation.py`,
   `sdk/lan_control.py` error codes.
3. **LAN protocol** — `sdk/lan_framing.py`, `sdk/lan_session.py`,
   `sdk/lan_socket.py` (real 0x55aa + session keys).
4. **MQTT session** — `sdk/mqtt_session.py`, `sdk/mqtt_client.py`,
   `sdk/mqtt_framing.py`, `sdk/mqtt_sign.py`.
5. **Repository/app layer** — `app/repository.py`, `app/resolver.py`,
   `app/dp101.py`, `app/manager.py`, `app/helper.py`.

## Phase 2 rebuild status

New `pypopur.sdk` package (all opcode-verified against smali):

| Module | Ports | Status |
|---|---|---|
| `sdk/_java.py` | TextUtils/Integer semantics, fastjson quirks | done |
| `sdk/_fastjson.py` | fastjson null-omission, ordered maps | done |
| `sdk/crypto.py` | AESUtil (ECB/PKCS5, hex upper), AesGcmUtil, MD5, CRC32 | done |
| `sdk/hexutil.py` | HexUtil/ByteUtils signed-byte semantics | done |
| `sdk/schema.py` | SchemaBean + SchemaMapper | done |
| `sdk/validation.py` | DevUtil checkSendCommond (bitmap quirk: any Integer passes) / checkReceiveCommond / encodeRaw / decodeRaw | done |
| `sdk/sando.py` | SandO (s=2, SAdd++, o=random*1e6+1000), SandRMap | done |
| `sdk/dedup.py` | qdddqdp 5 s window, remove-on-hit, low-power `& 0x1000` | done |
| `sdk/timestamp.py` | TimeStampManager (unix-seconds base, ms = base*1000+δ) | done |
| `sdk/mqtt_sign.py` | pbbppqb sign/CRC helpers | done |
| `sdk/mqtt_framing.py` | qpqddqd + per-pv outbound/inbound framing 1.1/2.0/2.1/2.2/2.3 | done |
| `sdk/mqtt_session.py` | bqbppdq manager, qpqbppd OEM creds, MqttConnectConfig, subscription bookkeeping | done |
| `sdk/device_id.py` | PhoneUtil.getDeviceID / generateRandomId | done |
| `sdk/lan_framing.py` | ddbdpqb + bbbdppp lpv-versioned request assembly | done |
| `sdk/device_cache.py` | DeviceRespBean/DeviceBean/ProductBean, ppqqqpb cache, ddpdbbp, pdppddb central ingest | done |
| `sdk/lan_control.py` | qqdbbpp (LAN + internet halves incl.
  "control by server" + HTTP backup + $bppdpdq/$qddqppb wrappers),
  bpqqdpq, dqdpbbd cid/ctype + DevCloudControlImpl + sendByHttp/
  DpPublish, dddpppb LocalControlModel, bddqdbd watchdog pipeline,
  qpbpqpq gates, FrameTypeEnum/ActiveEnum/HgwBean/
  ThingLocalControlBean, ThingUtil.compareVersion/checkHgwVersion/
  checkPvVersion | done |
| `sdk/comm_pipeline.py` | AbsThingDevice publishDps entries (2-arg,
  mode-enum, channel-list), publishDpsInPipeline chain build,
  checkDirectGateway BLE promotion, qqqbbbd base + 9 handlers
  (dppdqpp/dbbpdqp/qdqbdbd/bddqdbd/bqpdbqq/qqppqqd/pdpdpqp/
  dqqbppb/qpppqdb/qbdppbq), qpbpqpq DevModel (intranetControl/
  bppdpdq/bdpdqbp(Z)/sendDpsByApi/sendCloudDpsByApi/isIntranet/
  isCloudOnline), CommunicationEnum/ThingDevicePublishModeEnum/
  DataModelType, StatStripCallback (#-strip), PipelineAnalytics seam
  (qqpppdp/StatUtils) | done |
| `sdk/security.py` | ThingApiSignManager (whitelist, sort+`||` join,
  postData MD5-swap, `getRequestKeyBySorted`), MD5Util/swapSignString,
  ThingNetworkSecurity wrappers (getEncryptoKey/genKey/getChKey/
  computeDigest/encryptPostData), injectable cmd-1 signer | done |
| `sdk/atop.py` | ThingApiParams+ApiParams merge (initUrlParams,
  getUrlParams, getPostBody/getRequestBody, getEncryptPostDataString,
  thing→smartlife rewrite), NetworkStatics (ThingSmartNetWork),
  Business+RequestTask (101/102/105/108, TIME_VALIDATE_FAILED single
  retry, session-loss remap, decrypt+verify response, gzip header),
  DeviceApi (dbppbbp DP surface) | done |
| `sdk/discovery.py` | GwBroadcastMonitorService (CAS start, multicast
  lock seam, fixed_key.bmp security content, UDP 6650/6667/7000,
  APP_SEND_BROADCAST 0x25 @ pv5, `{"ip","from":"app"}` → 255.255.255.255
  :7000 period 6000, subnet re-send after 3000 ms, gwMap same-gwId
  overwrite / same-ip-different-gwId evict, 1000 ms drain → monitors,
  config-result fanout, dead-monitor removal), HgwBean fields,
  ActiveEnum (UNACTIVE 0/ACTIVING 1/ACTIVED 2/LOCAL_UNACTIVE 3/
  LOCAL_ACTIVED 4), DeviceActiveEnum.to, isAPDirectlyDevice
  (meta key presence), qpqbbpp ip validity, qbdpdpp
  ThingSmartHardwareManager (onFind addHgw routing incl.
  CONSTRUCTION/COMMERCIAL_LIGHTING branches, LAN backoff
  qpppdqb tracker — 1 s-burst illegal counter, 120 s disable window,
  60 s stale drop, onDevUpdate fanout + pdqdqbd event, school-time
  sync frame 0x18, getLocalKey/getLpv gates); `devRespWrap` now
  attaches `DeviceBean.hgw_bean` via injected `hardware.get_dev_id`
  and `checkGw` is implemented on `DevListCacheManager` | done |
| `sdk/low_power.py` | bdqqqbp LowPowerDeviceManager: awake() entry
  (1001/1002/1003 errors, communicationNode redirect, virtual→SUCCESS,
  low_power_wakeup meta gate, already-awake fast path via
  qpppdqb/pbbdddb + cloudConnectLastUpdateTime, callback registry
  dedup, existing-task short-circuit), wake task runnable (1 s repost,
  deadline → AWAKE_TIMEOUT), `m/w/<devId>` MQTT publish of big-endian
  CRC32(localKey), checkAwakeStatus business seam
  (`m.thing.device.low.power.connect.batch.get` v1.0, devIds JSON) +
  result handling (lowPowerConnect=false → flag+SUCCESS, empty→
  UNSUPPORT), dispatch_result (cancel task, drain callbacks),
  release(Z); LowPowerAwakeRsp (UNSUPPORT 1/SUCCESS 2/
  AWAKE_TIMEOUT 3), LowPowerConnectResult, ProductRefBean/
  DeviceBizPropBean beans + devRespWrap biz-prop fallback seam;
  `low_power_check_awake` (qdddbpp Business adapter), `MqttServerAdapter`
  (IMqttServer signature over MqttWireClient), `TimerHandler`,
  `$pdqppqb` status callback → release(false) | done |

Resolved since the Phase-1 audit:

- `IThingHardware`/`DevTransferService` JNI boundary — concrete real
  transport: `SocketThingNetworkApi`/`SocketThingNetworkInterface` in
  `sdk/lan_socket.py` (0x55aa/0x6699 framing, session-key swap, heartbeats,
  `sendBroadcast`/`listenUDP` sockets).
- UDP discovery — real `listenUDP` loop + `fixed_key.bmp` announcement
  decrypt in `sdk/lan_socket.py`; top-level `discovery.py` drives it.
- `DeviceApi.atop_publish` adapter serves the
  `DevCloudControl.atop_publish` seam (DpPublish order `gwId,devId,dps`);
  `pypopur.cloud.build_business`/`build_device_api`/`AtopCloudBackend`
  wire a `MobileAppProfile`+`MobileSession` into `Business`.
- cmd-1 signer **emulation-verified**: `doCommandNative(1, canonical)` =
  `hmac_sha256(GLOBAL_S, canonical)` (64 lowercase hex) — end-to-end
  cmd-1 emulation after a real cmd-0 derivation (`emu_cmd1.py`); the
  earlier "nested MD5 via `hmacWrap` @0x12eb4" note had emulated cmd
  2's helper. `getEncryptoKey`
  NULL-arg1: data = GLOBAL_S alone (`cbz x21` @0x14d18).
  `ThingApiSignManager`/`ThingNetworkSecurity` take bytes GLOBAL_S.
- Low-power awake binding — `PipelineTransport` auto-constructs
  `LowPowerDeviceManager` from the cloud backend's wire client +
  `device_api.business` (`MqttServerAdapter`, `low_power_check_awake`,
  `TimerHandler`) and binds `presenter._awake_fn = manager.awake`, the
  `MqttCommHandler.send` → `bpbqqdq.bdpdqbp(devId, 8000, cb)` path.
  `MqttWireClient.register_mqtt_callback` supplies the
  `IMqttServerStatusCallback` → `release(false)` hook. Still dormant
  for the mains-powered S7 (no `low_power_wakeup` configMeta →
  awake returns UNSUPPORT and `internet_send` proceeds, identical
  observable behavior to the former no-op seam).
- App layer is `src/pypopur/app/` — `dp101.py` (Dp101RunModeSet +
  Dp102SystemSettings + Dp125SelfCheckFault helpers), `dp_string.py`
  (DeviceDpStringParser + `d(Map)` + AOSP `JSONTokener` port),
  `resolver.py` (DeviceDpStateResolver merges + `S` derive),
  `manager.py` (UnifiedDeviceControlManager + DeviceState copy masks +
  listener bridge + m/o/p/q reflective cascade),
  `repository.py` (P/D0 merge + v0 cleaning-progress machine + q0/c0/l0/
  e0/k0/d0 DataStore paths + CleaningProgressMetadata + M/Q),
  `helper.py` (sendDeviceCommand orchestration). See `07-app-state.md`.

- Thing-model subsystem (`sdk/thing_model.py`) — the full link-message
  path: `qqbbddb` LinkFilterConvertUtil (incl. the
  `containsKey(abilityId)`/`payload.get(code)` quirk), `bdpqppd`/
  `bppdpdq`/`qqqpdpb` property/action/event converters (action send +
  receive store *original* values; event receive stores converted),
  `bbdppqp` type-spec validator (compat fall-through: unknown types and
  out-of-range value/bitmap return the input; enum/array/struct miss →
  null), `qpppdbb` singleton model cache (`None` version → `"1.0.0"`,
  empty string kept), `ddpdbbp.getThingModelWithPid`, `dbddpbp`/`dqqpqbq`
  link handlers with the `qqqbbbd` tail-reset chain quirk,
  `qpbpqpq.sendLinkMessageByMqtt/Http`, `qdbpqqq` link publish
  (`tylink/` topics, SandO envelope, `#`-appended stat errors,
  `thing_vlt9u1rn677ht6wxpnxlt9em1p4pfp2u` event), and the
  `bqbppdq.publishLinkWithTopic` wire adapter (plaintext
  `{"msgId","time","data"}`). `publishDps` routes `data_model ==
  THING_MODEL` through `convert_to_link_property` first. Dormant on the
  S7 (`THING_DP`).

Still open: nothing. `doCommandNative` cmd 0's Context/assets/cert chain was
re-emulated end-to-end in `popur-research/emu_cmd0.py` (see
`02-security.md` "Still open") — `read_keys_from_content` runs natively from
`libthing_security_algorithm.so`, the BMP steganographic key, cert SHA-256,
package name and app secret compose `GLOBAL_S` byte-exact equal to the
shipped `APP2_NATIVE_MASTER_HEX`.
