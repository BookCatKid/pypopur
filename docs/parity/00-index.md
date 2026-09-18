# Popur App 2.0.0 → pypopur parity spec

Canonical source: `popur-research/apktool` smali (jadx used only where present and
cross-checked). APK: `Popur-S7-v2.0.0.apk`, SHA-256
`326e6586c07f68bd86955a5f5553c6736b709e124f4d4eb663aac82e6074361b`.

Every entry cites `file:line` of physical smali/jadx lines. Parity bar:
behavior-identical (same decisions, state transitions, wire semantics; not
necessarily byte-identical where unobservable).

## Subsystem docs

- `01-dispatch.md` — publishDps pipeline, communication modes, channel
  eligibility, fallback semantics, command validation (checkSendCommond),
  RAW encode/decode at transport boundary.
- `02-security.md` — libthing_security port: runtime globals, getEncryptoKey,
  genKey, getChKey, computeDigest, AES-GCM envelope, t_cdc.tcfg.
- `03-http.md` — ATOP HTTP layer: request fields, signing, et=3 postData
  encryption, envelope unwrap, regions/endpoints.
- `05-mqtt.md` — MQTT session (connect auth, topics, pv-versioned
  framing 1.1/2.0/2.1/2.2/2.3) **and** LAN transport (control routing,
  500 ms watchdog + cloud fallback, lpv-versioned request assembly,
  DevTransferService / ThingNetworkApi native boundary, UDP discovery).
- `06-auth.md` — login/register flow: username token, RSA-MD5 password,
  email login, session (sid/ecode), home/device enumeration, localKey.
- `07-app-state.md` — DeviceRepository cache semantics, DataStore snapshots,
  DeviceDpStateResolver merge rules, TuyaDeviceBeanDpsReader.
- `08-bootstrap.md` — home/device enumeration: queryHomeList,
  newHomeInstance, getHomeDetail 3-task parallel fetch, the 8-API
  `thing.m.api.batch.invoke` batch, SDK cache merge, app reflection
  field surface.
- `09-dp-model.md` — DeviceDpConstants vocabulary, packed DP codecs
  (101 run-mode report, 102 system-settings bitfield, 103 timers,
  104 dustbin, 105 keys, 106/125 self-check, 22 activity, 112-124
  notifications), universal decodeToBytes coercion, DeviceRepository
  critical-DP post-command write.
- `10-app-control.md` — app-layer send orchestration (sendDeviceCommand),
  publishDps strategy chain, DeviceState flow, IDevListener proxy bridge.
- `11-events.md` — inbound DP event pipeline: EventBus models, qbqqdqq
  event center, ppdpppq per-device processor, IDevListener fan-out,
  DeviceDpStringParser/DeviceDpDataNormalizer, HomeViewModel merge +
  pending-action protection.
- `12-module-audit.md` — Phase 1 audit: per-module keep/fix/rewrite
  verdicts for the existing pypopur package against this spec, plus the
  list of missing subsystems.

## Cross-cutting notes

- `CommunicationEnum` type ids: LAN=0, MQTT=1, HTTP=2, BLE=3, SIGMESH=4,
  THING_MESH=5, THING_BEACON=6, OTHER=-1, THING_MATTER=8, YU_MQTT=12,
  CLOUD_MODE=100.
  (smali_classes3/.../bean/CommunicationEnum.smali:58-304)
