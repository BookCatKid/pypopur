# 05 — MQTT transport (ThingClips sdk.mqtt)

Canonical classes under `smali_classes3/com/thingclips/sdk/mqtt/`.
All smali paths below are relative to `/Users/simon/MyDocuments/gpt/popur-research/apktool/`.

## Session / connection — `bqbppdq` (MqttServerManager)

Singleton per tag (`dqdpbbd` static, ctor takes a `String` tag stored in
`pqdbppq`). `init()` (lines 245-341) requires `IThingGetBaseConfig` and
`MqttConnectConfig`; `initMqtt()` (343-578) builds `MqttConfigBean` then
selects the credentials provider (`pbpdpdp` interface) by app type
(lines 410-511):

| Condition | Implementation |
|---|---|
| `appTag == "industry"` | `dbppbbp` |
| `ThingSmartNetWork.mSdk == true` (OEM app — **Popur**) | `qpqbppd` |
| else | `qpbdppq` |

Then constructs `pqpbdqq` (the actual client wrapper) and registers a
`bqbppdq$pbbppqb` status callback.

### `initMqttConfig` (lines 580-1316), non-industry path

- `username` (bean field) = `PhoneUtil.getDeviceID(app) + "_" +
  md5AsBase64(uid + "sdkfasodifca")` (lines 683-757)
- `clientId` = `packageName + "_mb_" + username + "_" + tag` (766-1123)
- server = `BaseConfigInfo.domain.mobileMqttsUrl`, port =
  `pqpbpqd.qbqqdqq` = **0x22b3 = 8883**
- `serverUrl` = `"ssl://" + host + ":" + port`, `connectType = 1`
- bean: `cleanSession=true`, `qos=1`, `keepAlive=60`, `timeOut=15`,
  `retained=false`, `enableQuic=false`, `maxInflight=60`
  (`pqpbpqd.ppdpppq` = 0x3c), `willTopic = pqpbpqd.dpdbqdp`
  (= **"tuya/smart/will"** — `"thing/smart/will".replace("hing","uya")`),
  `sslKey=""`, `sslPassword=""` (1170-1315)

The bean's `userName` is *not* what goes on the wire — the connection
model (`mqttmanager/model/bdpdqbp.smali` ~1188-1452) pulls
`username`/`password` from the `pbpdpdp` provider:

- `MqttConnectOptions.setUserName(pbpdpdp.qddqppb())` if non-empty
- `MqttConnectOptions.setPassword(pbpdpdp.bppdpdq().toCharArray())` if
  non-empty
- `setServerURIs(configBean.mqttUrls)`, `setCleanSession`,
  `setConnectionTimeout(15)`, `setKeepAliveInterval(60)`,
  `setMaxInflight(60)`, `setIpAddress(host, ipAddress)` when both set
- SSL: `SSLSocketFactory` from `bdpdqbp.pppbppp()` trust manager +
  `qppddqq` wrapper

### OEM credentials — `qpqbppd.smali`

- `qddqppb()` = username =
  `partnerIdentity + "_v1_" + mAppId + "_" + getChKey(ctx, mAppId.bytes)
  + "_mb_" + token + last16` where `last16 =
  md5AsBase64(md5AsBase64(mAppId) + ecode)[len-16:]` (lines 264-476).
  `mAppId = ThingSmartNetWork.mAppId` (the APP2 client id).
- `bppdpdq()` = password = `doCommandNative(ctx, 2, ecode.bytes, null,
  ThingSmartNetWork.mD)` → string `v`; return `v[len/2-8 : len/2+8]`
  (16 chars centered); null → `"value ==null"` then same substring
  (lines 131-238).
- `bdpdqbp()` = user topic = `partnerIdentity + "/mb/" + uid`
  (lines 48-128).
- `pdqppqb()` refreshes `MqttConnectConfig` from base config.

(`qpbdppq` for reference: username = `config.token`, password =
`md5AsBase64(ecode)[8:24]`, userTopic = `"smart/mb/" + uid`.)

## Send chain — `qqdbbpp` (DevControlModel, `sdk/device/`)

The public send entry used by the comm pipeline. All under
`smali_classes3/com/thingclips/sdk/device/`.

### Device/sub-device resolution — `qqdbbpp.bdpdqbp(String)` (282-362)

`respBean = DevListCache.getDevRespBean(devId)`:

- `commId = respBean.communication.communicationNode`; if empty AND
  `isTripartiteMatter()` → `commId = devId`
- `nodeId = respBean.nodeId`; if `commId == devId` → `nodeId = ""`
- returns `{commId, nodeId}`; null respBean → `{devId, devId}`? — no:
  null → `commId=devId`, `nodeId` stays the (null) `respBean.nodeId`
  slot → effectively `{devId, null}` path; verify edge case.

### DP map build — `bdpdqbp(nodeId, dpsJson)` (401-531)

- nodeId non-empty → resolve sub-device by nodeId in
  `getSubDevList(devId)` → recurse with its devId
- else: `JSON.parseObject(dpsJson)` → **LinkedHashMap** (ordered);
  `DevUtil.checkSendCommond(devId, map)` → null on failure;
  `DevUtil.encodeRaw(devId, dpsJson, map)` mutates the map in place
  (returned String ignored); returns the map.

### `SandO` source — `bdpdqbp()` (364-399)

`SandRMap.getInstance().get(devId)`; missing → create + put. Then
`SAdd()` (s++) and return — **every send increments s**.

### LAN-first entry — `bdpdqbp(devId, nodeId, dpsJson, type, logKey, cb)`
(1163-1278)

1. `dev = cache.getDev(devId)`; null → `onError("11002", null)`
2. `map = bdpdqbp(nodeId, dpsJson)`; null → `onError("11001", null)`
3. `sandO = SAdd()`
4. `dev.getCommunicationOnline(LAN)` → log "dps send by local" → LAN
   send (554, below) wrapped in `qqdbbpp$bppdpdq`: **on LAN error →
   re-enters "control by server"** (640); onSuccess → cb.onSuccess
5. else → "control by server" (640)

### "control by server" — `bdpdqbp(dev, nodeId, type, dpsJson, logKey, sandO, cb)` (640-780)

- `!mqttServer.isRealConnect() && networkAvailable(ctx)` → HTTP path
  (988)
- `dev.isOnline` → if `!DevControllerEventAnalysis.isSubscribe(devId)`
  and MQTT plugin present → `subscribe("smart/mb/in/"+devId)`; then
  `dqdpbbd.sendCommand(devId, map, nodeId, type, logKey, sandO, cb)`
  wrapped in `qqdbbpp$qddqppb`: **on error → "start backup http send" →
  HTTP path** (988)
- `!isOnline` → `onError("10203", null)`

### HTTP path — `bdpdqbp(nodeId, dpsJson, cb, devId)` (988-1095)

- map null → `11001`
- nodeId empty → `dqdpbbd.bdpdqbp(gwId=devId, devId=devId,
  fastjson(map, WriteMapNullValue), cb)`
- nodeId → `getSubDev(devId, nodeId)` → subDevId; empty → `10203`;
  else `sendByHttp(gwId=devId, devId=subDevId, json, "")`
- after dispatch: posts `pppbppp` runnable delayed **500 ms** on a
  handler (stat/tracking)

`sendByHttp` (1454-1637): builds `DpPublish{gwId, devId, dps, pcc}` →
`dbppbbp.bdpdqbp(DpPublish, listener)` (ATOP business call).
`pdqdbdd`-typed callbacks get `event_sdk_instruct_http` stat.

### `dqdpbbd.sendCommand` (1639-1813)

- dev null → `11002` "dev==null"
- `pv >= 1.1` → "dps send by mqtt" → `bdpdqbp(devId, map, dev, nodeId,
  type, logKey, sandO, cb)` (861)
- else → "dps send by Http" → `sendByHttp(gwId=devId, devId=devId,
  fastjson(map, WMNV), "", cb)`

### MQTT data envelope — `bdpdqbp(devId, map, dev, nodeId, type, logKey, sandO, cb)` (861-1110)

- `data = {}`
- `cadv >= "1.0.2"` → `bdpdqbp(devId, nodeId, type, data)` may add
  `cid`/`ctype` (sub-device addressing; only when nodeId≠devId,
  non-empty, and subdev resolves — IR/product `bizAttribute&1` path
  strips `-v-` suffix); `logKey` non-empty → `data["mbid"]=logKey`;
  `data["dps"]=map`
- elif `!isVirtual` AND (`cadv >= "1.0.1"` OR `isBleMesh` OR `hasZigBee`
  OR (`is433Wifi` AND nodeId≠"" AND parentDevId≠"")) → same
  cid/ctype helper; `data["dps"]=map`
- else → `data["devId"]=devId; data["dps"]=map`; **and if `2.0 <= pv <
  2.1`** → `data["gwId"]=devId`
- → `bbppbbd.bdpdqbp(devId, pv, localKey, data, sandO, cb)`

### `bbppbbd` → `MqttControlBuilder` (bbppbbd 377-556)

`bbppbbd.bdpdqbp(devId, pv, localKey, data, sandO, cb)` calls the
7-arg form with **protocol = 5** (`const/4 v5, 0x5`). Builder:
`data=data, localKey=localKey, pv=pv, protocol=5, topicId=devId,
sn=sandO.s, o=sandO.o, s=sandO.s, t=(int)TimeStampManager.
getCurrentTimeStamp()` → `IMqttServer.publishDevice(builder, cb)`.
`pdqdbdd`-typed callbacks get `event_sdk_instruct_mqtt` stat.

## Publish path — `publishDevice` (`bqbppdq` ~3290-3556)

- null builder → error `100001` "MqttControlBuilder is empty"
- not `isRealConnect` → error `6000` "mqtt is not connect"
- topicId = `builder.getTopicId()` (= devId)
- if `!isSubscribe("smart/mb/in/"+topicId)` → subscribe it (null cb)
- intercept listener (`pdqdqbd.pdqppqb()`): when `pqdbppq=="DEFAULT"`
  and listener non-null → `interceptPublish("smart/mb/out/"+topicId)`;
  returned `uniTag != pqdbppq` → re-dispatch
  `pdqdqbd.pdqppqb(uniTag).publishDevice(builder, cb)` (alternate MQTT
  server)
- else build `bddqqbb` record → `ppdpppq` pv-dispatch → framed bytes →
  `bqbppdq$qpppdqb` callback: publish `smart/mb/out/<topicId>`;
  **protocol == 0x12e (302)** → `bqbppdq.e()` special path instead of
  `publish()`; success → `c(topicId, protocol, messageId)` bookkeeping +
  `PublishAndDeliveryCallback.publishComplete(clientId, msgId,
  protocol)`

`publish(topic, payload, qos, retained, cb)` (3055+): not connected →
`6000` "mqtt is not connect".

`send302Message`/`send302BackupHttp` (2080-2382): protocol-302 publish
fallback — `send302Message` is a plain `publish(topic, data, qos=0,
retained=false)`; `send302BackupHttp` is rate-limited to once/1000 ms
(field `dpdbqdp`) and calls `IThingDeviceOperator.sendMQTTDataByHttp(
devId, data, cb)` — the framed payload goes to the device via the ATOP
HTTP channel instead of MQTT.

### `bddqqbb` — MqttControlBuilder fields

| Setter | Field | Getter | Meaning |
|---|---|---|---|
| `bdpdqbp(Object)` | `bdpdqbp` | `pdqppqb()` | `data` |
| `bdpdqbp(String)` | `bppdpdq` | `bppdpdq()` | `localKey` |
| `bdpdqbp(int)` | `pbpdpdp` | `qddqppb()` | `o` |
| `pdqppqb(int)` | `qddqppb` | `pppbppp()` | `protocol` |
| `pdqppqb(String)` | `pdqppqb` | `pbbppqb()` | `pv` |
| `bppdpdq(int)` | `pbddddb` | `qpppdqb()` | `s` |
| `qddqppb(int)` | `pppbppp` | `pbddddb()` | `sn` |
| `pppbppp(int)` | `pbbppqb` | `pbpdpdp()` | `t` (int; init `-1`) |
| `bppdpdq(String)` | `qpppdqb` | `pbpdbqp()` | `topicId` |

`qdddbpp` (frame context, `qdddbpp.smali` ctor) copies builder → fields:
`bdpdqbp`=topicId, `pdqppqb`=data, `bppdpdq`=pv, `qddqppb`=localKey,
`pppbppp`=protocol, `pbbppqb`=sn, `qpppdqb`(long)=t, `pbddddb`=o,
`pbpdpdp`=s.

### `SandO` (`smart/interior/device/confusebean/SandO.smali`)

- `s` starts at **2**, `SAdd()` increments by 1 (sequence counter)
- `o` = `(int)(Math.random()*1_000_000) + 1000` — random origin id per
  instance
- Builder gets `sn=s`, `s=s`, `o=o` from the caller (`bbppbbd` cloud
  path: `Sn=SandO.s, O=SandO.o, S=SandO.s, T=(int)now`)

## Outbound framing — `ppdpppq.smali` dispatch

`ppdpppq.bdpdqbp(cb)` selects by `Float.parseFloat(pv)` via
`ThingUtil.checkPvVersion` (returns false on empty/unparseable):

| pv | Class | File |
|---|---|---|
| ≥ 2.3 | `dbbpbbb` | dbbpbbb.smali |
| ≥ 2.2 | `qpbpqpq` | qpbpqpq.smali |
| ≥ 2.1 | `bpqqdpq` | bpqqdpq.smali |
| ≥ 2.0 | `qqdbbpp` | qqdbbpp.smali |
| ≥ 1.1 | `dqdpbbd` | dqdpbbd.smali |
| else | no-op (no callback) | — |

`ByteUtils.intToBytes2(i)` = **4-byte big-endian** (name is misleading).
`ByteUtils.contact` = concat. `bytesToInt2` = 4-byte BE read.

### pv 2.3 — `dbbpbbb`

- bean = `PublishBean2_3{data, protocol, t}` (qpqddqd.pdqppqb)
- `head = pv.getBytes() || be32(s) || be32(o) || [0x00]` (12 bytes for
  pv="2.3")
- `enc = AesGcmUtil.encryptBytes2BytesAppendNonce(localKey.getBytes(),
  fastjson(bean, WriteMapNullValue).getBytes(), head)`
  = `nonce(12B, SecureRandom-strong) || AES/GCM/NoPadding ct+128b tag`
  with `head` as AAD (AesGcmUtil.smali 243-303, 305-365)
- payload = `head || enc`
- encrypt null → error `11003` "aesBytes==null"

### pv 2.2 — `qpbpqpq`

- bean = `PublishBean2_2{data, protocol, t}` (qpqddqd.bdpdqbp(J,I,Object))
- `aesBytes = AESUtil("AES", localKey.getBytes()).encryptWithBytes(
  fastjson(bean, WriteMapNullValue))` — AES/ECB/PKCS5Padding
- `crc = be32(crc32(be32(s) || be32(o) || aesBytes))`
  (`pbbppqb.bdpdqbp(II[B)`, lines 574-604)
- payload = `pv.getBytes() || crc || be32(s) || be32(o) || aesBytes`
- encrypt null → `11003` "aesBytes==null"

### pv 2.1 — `bpqqdpq`

- bean = `PublishBean2_1{data, protocol, t, s=sn}`
  (qpqddqd.bdpdqbp(J,I,I,Object))
- `enc = AESUtil(localKey).encryptWithBase64(fastjson(bean,
  WriteMapNullValue))` → base64 string; empty → `11003` "aesBytes==null"
- `sign = pbbppqb.bdpdqbp(pv, enc, localKey)` =
  `md5("data="+enc+"||pv="+pv+"||"+localKey).toLowerCase()[8:24]`
  (16 hex chars); null → `11004` "sign==null"
- payload = `(pv + sign + enc).getBytes()`

### pv 2.0 — `qqdbbpp` (mqtt)

- bean = `PublishBean{pv, t, gwId=topicId, protocol,
  data=fastjson(data, WriteMapNullValue)}`
  (qpqddqd.bdpdqbp(String,J,String,I,String))
- `qpqddqd.bdpdqbp(bean, localKey)`: `bean.data =
  AESUtil(localKey).encrypt(bean.data)` → **hex string** in place
- `bean.sign = pbbppqb.bdpdqbp(bean, localKey)` =
  `md5(canonical).toLowerCase()` where canonical = sorted-keys `k=v`
  joined by `||` over whitelist `{data,gwId,protocol,pv,t}` + `||localKey`
  (pbbppqb 290-307, 359-497, 499-572)
- payload = `fastjson(bean).getBytes()` — plaintext JSON envelope

### pv 1.1 — `dqdpbbd` (mqtt)

- bean = `PublishBean2_2{data, protocol, t}` — **unencrypted**
- `dataBytes = JSON.toJSONBytes(bean)`; null → error `"dp error"`
  "dataBytes==null"
- `crc = be32(crc32(be32(s) || be32(o) || be32(crc32(dataBytes)) ||
  localKey.getBytes()))` (`pbbppqb.bdpdqbp(II[BLjava/lang/String;)`,
  606-677)
- payload = `pv.getBytes() || crc || be32(s) || be32(o) || dataBytes`

## Inbound dispatch — `messageArrived` → `parseMessage` (1424-2022)

Topic prefix order:

1. `pqpbpqd.bqqppqq` = **"tylink/"** (`"thinglink/".replace("hing","y")`,
   `pqpbpqd.<clinit>` 93-109) → payload parsed as JSON →
   `MqttMessageRespParseListener.onMqttDpReceivedSuccess(topic, -1, json)`;
   exception → `onMqttDpReceivedError(topic, "ParseMqttMessageError",
   e.toString())`
2. `yu/mb/in/` → `{"data": <raw payload bytes>}` → same callbacks
3. `m/m/i/` → per `MqttFlowRespParseListener` (`qddqppb` list):
   `devId = topic.replace("m/m/i/", "")` (ALL occurrences);
   `localKey = listener.getLocalKey(devId)`; skip listener if empty;
   `pqdppqd.bdpdqbp(localKey, payload)` →
   `listener.onSuccess(topic, decrypted)`; exception → log only
4. everything else (incl. `smart/mb/in/`) → per listener: `dqddqdp`
   builder {topic, success cb, listener.getTopicSuffix(), error cb,
   payload} → `qbqddpp` parser; decoder errors arrive via
   `onMqttDpReceivedError(topic, code, msg)`; exceptions →
   `onMqttDpReceivedError(topic, "6002", "ParseMqttMessageError"+e)`

### `pqdppqd` — m/m/i/ flow frame

- `bdpdqbp([B)` = CRC32 check: `be32(payload[-4:]) == crc32(payload[:-4])`
- `bdpdqbp(localKey, payload)`: after CRC check reads 4 BE **shorts** at
  offsets 0,2,4,6 = `(magic, flags, encFlag, len)`:
  - `0x55aa, 0, 0` → `AESUtil(localKey).decryptWithBytes(payload[8:8+len])`
  - `0x55aa, 0, 1` → raw `payload[8:8+len]`
  - `0x55aa, 0, other` → raw `payload[8:8+len]`
  - else → null
  (pqdppqd.smali 93-328; AES-ECB at 330-377)

### `qbqddpp` — generic inbound parser (qbqddpp.smali)

`bdpdqbp(cb)` (159-488):
1. `pv3 = payload[0:3]` as default-charset string
2. `pv3` starts with `"{"` → plaintext JSON → `pdqppqb(topic, json, cb)`
   (565-668):
   - topic starts `smart/mb/in/` → `bdpdqbp(topic, json, cb)` (490-562):
     - `json.protocol == 0x10` → `cb.bdpdqbp(protocol, json)` as-is
     - `json.pv == "2.0"` → signed path `bdpdqbp(I,String,JSONObject,cb)`
       (36-157): `getLocalKey(topic)` empty → `F101` "localKey == null";
       `pbbppqb.bdpdqbp(json, localKey).lower() != sign.lower()` →
       `11004` "sign is not equals"; else `data =
       AESUtil.decrypt(json.data, localKey)` → parse JSON →
       `json.data = parsed` → `cb.bdpdqbp(protocol, json)`
     - else → `cb.bdpdqbp(protocol, json)`
   - other topics → `cb.bdpdqbp(json.protocol, json)`
3. binary path (non-`{`):
   - `localKey = qqpdpbp.getLocalKey(topic)` — called with the FULL
     topic, before any stripping; empty → return silently (no error)
   - for each `suffix` in listener's `getTopicSuffixes()`: if
     `topic.startsWith(suffix)` → `topicId = topic - suffix` is computed
     but **discarded** (dead code — decoders get the full topic as
     "topicId"); store localKey + pv3 on the builder; `F101`
     "localkey ==null" if empty; dispatch by pv3 (via `checkPvVersion`
     = `!empty && Float.valueOf(pv) >= f`, no 'v' strip, throws on
     malformed):
     - ≥2.3 `dbpdpbp`, ≥2.2 `qbpppdb`, ≥2.1 `pdbbqdp`, ≥1.1 `qqqpdpb`,
       else log only
   - (loop continues over remaining suffixes — one cb call per match)

### Device listener — `qqpqqpq` (sdk/device)

The app's concrete `MqttMessageRespParseListener` for device topics:

- `getTopicSuffix()` (461-490) = `{"smart/mb/in/", "m/dg/",
  bdpdqbp()}` — the third element is the user-topic helper
  (`partnerIdentity + "/mb/" + uid`), not a pv version.
- `getLocalKey(topic)` (300-459): strips `smart/mb/in/` or
  `smart/mb/out/` → devId → `DevListCache.getDevRespBean(devId)
  .getLocalKey()`; BlueMesh/SigMesh localKey fallback when the bean is
  absent; null when neither resolves.
- `isDataUpdated(topic, s, o)` (492-…): strips `smart/mb/in/` then
  `m/dg/` → devId → `qdddqdp.isDataUpdated(devId, s, o)` — the same
  5000 ms dedup store as LAN inbound.

Ported → `pypopur.events.DeviceEventListener` +
`pypopur.events.PopurMqttEvents` (session → credentials → TLS wire
client → subscriptions → `dispatch_inbound_message` → `DeviceEvent`
callbacks), `pypopur.events.build_mqtt_credentials` (the
`UserConfigSessionLogoutManager$6` config: `token` = sid, `appTag` =
`"os"`), and `pypopur.events.make_central_ingest_sink` which routes
decoded DP pushes through `CentralDpIngest.ingest` (`from_cloud=true`)
so MQTT updates merge into `DevListCacheManager` exactly like the app.

### Inbound decoders

**`dbpdpbp` (2.3)**: layout `pv3 || s(4B@3) || o(4B@7) || flag(1B@11)
|| ct(12..)`; AAD = `payload[0:12]`; dedup `isDataUpdated(topic, s, o)`
→ `12003` "cloud command repeat with s:.. o:.."; decrypt =
`AesGcmUtil.decryptBytesAppendedNonce2Bytes(localKey.bytes, ct, aad)` →
UTF-8 JSON; empty → `12001` "mqtt2_3: data parsing failure"; missing
`protocol` → `12004` "protocol is not exist"; else
`cb(protocol, json)` (dbpdpbp.smali 123-281)

**`qbpppdb` (2.2)**: layout `pv3 || crc(4B@3) || s(4B@7) || o(4B@11)
|| ct(15..)`; dedup same → `12003`; `crc32(payload[7:]) != be32(payload
[3:7])` → `12002` "mqtt2_2: signature is not match signStrBt..";
decrypt = `AESUtil.decryptWithBytes(ct)` → UTF-8 → JSON; `12001`/
`12004` same (qbpppdb.smali 123-326)

**`pdbbqdp` (2.1)**: payload string = `pv3 + sign(16) + b64`;
`sign = str[3:19]`, `b64 = str[19:]` (via substring(3) then [0:16] /
[16:]); verify `pbbppqb.bdpdqbp(pv, b64, localKey) == sign` →
`12002` "signature is not match 2_1"; decrypt =
`AESUtil.decryptWithBase64(b64)` → JSON; `12001` "dealWithDeviceTopic
2_1 data parsing failure"; `12004` missing protocol (pdbbqdp.smali
29-200)

**`qqqpdpb` (1.1)**: layout `pv3 || crc(4B@3) || s(4B@7) || o(4B@11)
|| data(15..)`; dedup → `12003`; verify `crc32(s || o ||
be32(crc32(data)) || localKey.bytes) == be32(payload[3:7])` → `12002`
"mqtt1_1: signature is not match signStrBt.."; data → UTF-8 JSON;
`12001` "dealWithDeviceTopic1_1 data parsing failure"; missing
`protocol` → `12004` "protocol is not exist null" (note the trailing
"null" — distinct from the 2.x message) (qqqpdpb.smali 123-609)

Ported → `pypopur.sdk.mqtt_framing` (`build_payload_*`,
`build_mqtt_publish`, `parse_inbound_*`, `MqttFrameError(code, msg)`).

## LAN transport — `bddqdbd` → `qpbpqpq` → `qqdbbpp` → `bpqqdpq` → `dddpppb`

### Pipeline handler — `bddqdbd.smali` ("ThingLanCommPipeline")

`pdqppqb(command, cb)` (85-167):
1. posts watchdog runnable on main Handler, delay **500 ms**: if
   `answered[0]==false` → log `"LAN request timeout, fallback to
   internet"` → `qpbpqpq.bppdpdq(command, cb)` (internet send)
2. `qpbpqpq.intranetControl(command, innerCb)` →
   `dbqqppp.pdqppqb(command, innerCb)` = `qqdbbpp.pdqppqb`
3. innerCb.onError → `answered=true`, remove watchdog → log
   `"LAN control error"` → **unconditional cloud fallback**
   `qpbpqpq.bppdpdq(command, cb)`; stat event 9 unless error message
   ends with `"#"` (`bddqdbd$bdpdqbp.onError` 61-202)
4. innerCb.onSuccess → `answered=true`, remove watchdog, cb.onSuccess

Note: a late LAN response after the watchdog fired is not suppressed —
both callbacks can run (the flag only guards the watchdog itself).

### Gate — `qpbpqpq.smali`

- `isIntranetControl()` → hardware plugin → `getDev(devId)` →
  `hgwBean.active` ∈ {`ACTIVED`, `LOCAL_ACTIVED`}; false if plugin /
  device / hgw missing
- `bppdpdq(command, cb)` → `dbqqppp.bdpdqbp(command, 0, cb)` — the
  internet send (`qqdbbpp.bdpdqbp(String,int,cb)`, line 782)
- `isCloudOnline()` → dev cache; if `communicationId != devId` also
  checks the communication device; requires cloud-online flag

### LAN send — `qqdbbpp.pdqppqb(data, cb)` (2299-2340)

`sandO = SAdd()`; `{commId, nodeId} = bdpdqbp(devId)`;
`dev = cache.getDev(commId)` (no null check here — NPE risk if
removed); → `bdpdqbp(dev, nodeId, 0, data, sandO, "", cb)` (554-638):

- `map = bdpdqbp(nodeId, data)`; null → `onError("11001", null)`
- `dev.cadv < "1.0.1"` AND `!hasZigBee` AND `!isBleMesh` →
  `bpqqdpq.bdpdqbp(devId, map, sandO, cb)` — **old CONTROL frame**
- else → `bpqqdpq.bdpdqbp(devId, nodeId, 0, map, sandO, "", cb)` —
  **CONTROL_NEW frame**

### Payload build — `bpqqdpq.smali` (DevLocalControlImpl)

**New style** (`bdpdqbp(devId, nodeId, type, map, sandO, logKey, cb)`,
34-85):
- `obj = {}`; `dqdpbbd.bdpdqbp(devId, nodeId, type, obj)` adds
  `cid`/`ctype` for sub-device addressing (same helper as MQTT path)
- logKey non-empty → `obj["mbid"] = logKey`
- `obj["dps"] = map` (LinkedHashMap)
- → `dddpppb.bdpdqbp(devId, obj, sandO, FrameTypeEnum.CONTROL_NEW, cb)`

**Old style** (`bdpdqbp(devId, map, sandO, cb)`, 87-205):
- `obj = {"dps": map, "devId": devId}`
- if hardware `getDevId(devId)` hgwBean exists AND
  `checkHgwVersion(hgw.version, 1.1f)` → `obj["t"] =
  TimeStampManager.getCurrentTimeStamp()` (long)
- if `BaseConfigInfo.uid != null` → `obj["uid"] = uid`
- → `dddpppb.bdpdqbp(devId, obj, sandO, FrameTypeEnum.CONTROL, cb)`

**`checkHgwVersion` quirk** (`ThingUtil.checkHgwVersion`): strips every
`"v"` then `Float.valueOf()` — a multi-segment lpv like `"3.3.0"`
throws → caught → **false** (no `t` field).  Only single-segment lpvs
(`"3.4"`, `"1.2"`…) pass the parse.

### Sub-device addressing — `dqdpbbd.bdpdqbp` (43-165)

`(gwDevId, nodeId, ctype, obj)`:
1. `nodeId == gwDevId` or `nodeId` empty → return untouched
2. `sub = cache.getSubDev(gwDevId, nodeId)` → `cache.getDev(sub.devId)`
   → product bean; if product `hasInfrared()` **or**
   `bizAttribute & 1 == 1`:
   - `nodeId` contains `"-v-"` → `nodeId = nodeId[:lastIndexOf("-v-")]`
   - else → skip flag (nothing added)
3. skip flag unset → `obj["cid"] = nodeId; obj["ctype"] = ctype`

Note: the infrared/`-v-` trim only applies when the sub-device is
actually resolvable under the **full** nodeId; an unknown `"-v-"` node
is added verbatim.

### `qqdbbpp` node/comm resolution — `bdpdqbp(devId)` (282-362)

Returns `{commNode, nodeId}`:
- respBean null → `{devId, devId}`
- else `commNode = communication.communicationNode` (NPE if the module
  is absent); when empty AND `isTripartiteMatter()` (accessType==1) →
  `commNode = devId`
- `nodeId = deviceTopo.nodeId`, forced to `""` when `commNode == devId`

`getSubDevList(devId)` (ppqqqpb 4118-4283): all cached beans whose
`topo.parentDevId == devId` **or** `meshId == devId` (NPE on a bean
with no `deviceTopo`).

### Frame/active enums

`FrameTypeEnum` (`interior/enums/FrameTypeEnum.smali`) — CONTROL `0x07`,
STATUS `0x08`, HEART_BEAT `0x09`, DP_QUERY `0x0A`, CONTROL_NEW `0x0D`,
DP_QUERY_NEW `0x10`, DP_QUERY_GENERAL `0x12`, LAN_GW_ACTIVE `0xF0`,
LAN_SUB_DEV_REQUEST `0xF1`, LAN_DELETE_SUB_DEV `0xF2`,
LAN_REPORT_SUB_DEV `0xF3`, LAN_SUB_DEV_STAUS `0xE1`, … (full table in
`pypopur/sdk/lan_control.py::FrameTypeEnum`).

`ActiveEnum` — `UNACTIVE=0`, `ACTIVING=1`, `ACTIVED=2`,
`LOCAL_UNACTIVE=3`, `LOCAL_ACTIVED=4`; `isIntranetControl` accepts
`{2, 4}` only.

`HgwBean` fields: `active`, `encrypt`, `gwId`, `ip`, `version` (lpv),
`token`, `uuid`, `productKey`, `lastSeenTime`, `sl`, `ability`, `mode`.

### Wire handoff — `dddpppb.smali` (LocalControlModel)

`bdpdqbp(devId, data, sandO, frameType, cb)` (32-120):
- `dev = cache.getDev(devId)`; null → `11005` "device is not exist"
- `hgw = dev.hgwBean`; null → `11005` "device is not local online"
- `lpv = hgw.version`; `localKey = hgw.isEncrypt ? dev.localKey : null`
- → 8-arg (550-705) with **protocol = 5**: builds
  `ThingLocalControlBean{data, devId, lpv, s=sandO.s, o=sandO.o,
  t=TimeStampManager.getCurrentTimeStamp(), protocol=5,
  frameTypeEnum=frameType.getType(), localKey}` →
  `IThingHardware.control(bean, dddpppb$bdpdqbp-wrapper)` (wrapper
  decoded below).
- `bdpdqbp(devId, data)` (232-418) is a pre-send data-transform hook
  (pid/subId/category_code/dps scene-type normalization; detail TBD).

`dddpppb$bdpdqbp` wrapper: onError → forwards `onError(code, msg+"#")`
(the trailing `#` tells the comm-pipeline handler a stat was already
recorded) + stat event with lpv/devId/data/sandO/protocol/frameType;
onSuccess → cb.onSuccess + stats + `thing_9v0xeqce...` event for
CONTROL/CONTROL_NEW frames.

## Internet send — "control by server" (`qqdbbpp` 630-790)

`bdpdqbp(dev, nodeId, type, dpsJson, logKey, sandO, cb)`:

1. `!bpbqqdq.bdpdqbp().pdqppqb()` (mqtt-up flag) **and**
   `networkAvailable` → HTTP path `bdpdqbp(nodeId, data, cb, devId)`
   (988-1055) immediately.
2. else if `dev.getIsOnline()` (resp `cloud_online`):
   - `!DevControllerEventAnalysis.isSubscribe(devId)` + mqtt plugin →
     `mqtt.subscribe("smart/mb/in/"+devId, null)`
   - `bdpdqbp(devId, data, nodeId, type, logKey, sandO, cb)` →
     `build_dp_map` → `dqdpbbd.sendCommand(devId, map, nodeId, type,
     logKey, sandO, qddqppb-cb)`
3. else → `cb.onError("10203", null)` (message is null, not a string).

Wrappers:

- `qqdbbpp$bppdpdq` (LAN→server): onError → re-invokes the server
  method with same args; onSuccess → forward.
- `qqdbbpp$qddqppb` (MQTT→HTTP): onError → logs
  `"controlByServer send dp failed : <msg>, start backup http send"` →
  `bdpdqbp(nodeId, data, cb, devId)`; onSuccess → forward.

HTTP backup `bdpdqbp(nodeId, data, cb, devId)` (988-1055):
- `build_dp_map` null → `cb.onError("11001", null)` — **no cb
  null-check** (NPE when cb is null).
- nodeId empty → `dqdpbbd.sendByHttp(devId, devId, json, "")`.
- else `sub = getSubDev(devId, nodeId)` → found →
  `sendByHttp(devId, subDevId, json)`; not found →
  `cb.onError("10203", null)`.
- always posts a 500 ms `pppbppp` runnable →
  `bpbqqdq.queryDev(subDevId ?: this.devId)` — cloud refresh.

### `dqdpbbd` — DevCloudControlImpl

`sendCommand(devId, map, nodeId, type, logKey, sandO, cb)` (1639-1790):
- `dev = bpbqqdq.getDev(devId)`; null → `onError("11002", "dev==null")`
- `checkPvVersion(dev.pv, 1.1f)` → "dps send by mqtt" →
  `bdpdqbp(devId, map, dev, nodeId, type, logKey, sandO, cb)` (861)
- else → "dps send by Http" → `sendByHttp(devId, devId,
  toJSONString(map, WriteMapNullValue), "", cb)`

`sendByHttp(gwId, devId, dps, pcc, cb)` → `DpPublish{gwId, devId, dps,
pcc}` → `dbppbbp.bdpdqbp` → ATOP **`thing.m.device.dp.publish` v1.0**,
postData `{gwId, devId, dps[, pcc]}`, `sessionRequire=true`.

MQTT payload build `bdpdqbp(devId, map, dev, nodeId, type, logKey,
sandO, cb)` (861-1030):
- `compareVersion(cadv, "1.0.2") >= 0` → `{cid?,ctype?,mbid?,dps}`
  (cid/ctype via `dqdpbbd` static helper; mbid when logKey non-empty)
- else if `!virtual` AND (`cadv ≥ 1.0.1` OR `isBleMesh` OR `hasZigBee`
  OR (`is433Wifi` AND nodeId AND parentDevId non-empty)) →
  `{cid?,ctype?,dps}` — **no mbid** on this branch
- else → `{devId, dps}`; when `!(pv ≥ 2.1) && pv ≥ 2.0` also `gwId`
- then `bbppbbd.bdpdqbp(devId, pv, localKey, obj, sandO, cb)` →
  `MqttControlBuilder{data, localKey, pv, protocol=5, topicId=devId,
  sn=sandO.s, o=sandO.o, s=sandO.s, t=(int)ts}` →
  `IMqttServer.publishDevice`

`DeviceBean.is433Wifi`: `product.has433()` (`capability & 0x20000` or
`& 0x4000`) AND (virtual → `product.hasWifi()`; non-virtual →
`communicationId == devId`).

`DeviceBean.getCommunicationId` = `communication.communicationNode`
(`devRespWrap` copies it to `communication_id`).

### `bqbppdq.publishDevice(builder, cb)` (3269-3419)

1. builder null → `onError("100001", "MqttControlBuilder is empty")`
2. `!isRealConnect()` → `onError("6000", "mqtt is not connect")`
3. `!isSubscribe("smart/mb/in/"+topicId)` → `subscribe(topic, null)`
   — marks the topic pending (`FALSE`) in the subscribe map
4. DEFAULT tag + intercept listener → reroute to the uniTag's
   `IMqttServer.publishDevice`
5. `bddqqbb{data, localKey, o, protocol, pv, s, sn, t, topicId}` →
   `ppdpppq` dispatch → framing handler →
   `bqbppdq$qpppdqb` → publish `"smart/mb/out/"+topicId`
   (protocol 302 → `e()` alternate publish)

### Hardware layer — `dpppdpq` (sdk/hardware) → `ddqpdpp` → `bbbdppp`

`IThingHardware.control(bean, cb)` (dpppdpq 856-971):
1. builds `ddqpdpp` record {data, devId, frameType, protocol, localKey,
   lpv, t, o, s} — `ddqpdpp.smali` setter/getter map:
   `bdpdqbp(Object)`→data, `bdpdqbp(String)`→devId, `bdpdqbp(int)`→
   frameType, `bppdpdq(int)`→protocol, `pdqppqb(String)`→localKey,
   `bppdpdq(String)`→lpv, `bdpdqbp(J)`→t, `pdqppqb(int)`→o,
   `qddqppb(int)`→s
2. `ddqpdpp.bdpdqbp()` → `bbbdppp` — **lpv-version dispatcher**
   (`bbbdppp.bdpdqbp` 36-300):
   - lpv ≥ 3.4 → `qbqppdb`
   - lpv ≥ 3.2 → `bdqbdpp`
   - lpv ≥ 3.1 → `bpbqpqd`
   - lpv == "1.1" → `qdbpqqq`
   - else → `bbppbbd` (v1.0)
3. on HRequest built → `dpppdpq.control(devId, frameType, bytes, cb)`
   (973-988) → `bdbdqdq.bdpdqbp()` = `bdbbqqd` →
   `GwTransferModel.bdpdqbp(devId, frameType, bytes, cb)` (511-559):
   closed → `11005` "dev transfer is closed"; else runs on
   ThingExecutor single thread → `DevTransferService` AIDL
   (`thing.intent.action.tcp`, package `thing`)

### lpv 3.4 request assembly — `qbqppdb.smali` (86-184)

- `HRequest{devId, type=frameType}`
- inner = `{protocol: <protocol=5>, data: <data obj>, t: <t>}` →
  `fastjson(inner, WriteMapNullValue).getBytes()`
- `req.data = lpv.getBytes() || [0,0,0,0] || be32(s) || be32(o) ||
  jsonBytes` — i.e. `"3.4" \x00*4 s(4BE) o(4BE) json`

### Socket + handshake — `DevTransferService`
(`smart/android/hardware/service/DevTransferService.smali`)

`sendBytes(devId, type, data)` (1765-2033):
- lpv ≥ 3.5 → `ThingNetworkInterface.sendBytes2(data, len, type, devId)`
- lpv ≥ 3.4 && `hgw.active == 2` (LOCAL_ACTIVED) → `sendBytes2`
- else → `ThingNetworkInterface.sendBytes(...)`
- return `-1` or `-2` → `onGwOnlineChanged(devId, false)` (mark LAN
  offline); return code → string returned to caller
- hardwareLog type 8 on success / 12 on failure

`buildConnect(hgw, localKey, netId)` (290-684):
- registers `LinkCloseCallback` + `LanHandShakeCallback` on
  `ThingNetworkInterface`
- localKey non-null → `connectDeviceWithKey(gwId, localKey,
  [LAN_PROTOCOL_VERSION_3_5 if version≥3.5 else default], netId)` →
  `checkConnectResult` → `startSwapKey(gwId, localKey)` (3.4 session-key
  swap)
- localKey null → version≥3.5 → `connectDeviceWithKey(gwId, null,
  LAN_PROTOCOL_VERSION_3_5, netId)`; else `connectDevice(gwId, netId)`
  → `connectSuccess`

`ThingNetworkInterface` → `ThingNetworkApi` = JNI natives in
`libnetwork-android.so`: `sendBytes`, `sendBytes2`, `connectDevice`,
`connectDeviceWithKey`, `startSwapKey`, `encryptAesData`,
`parseAesData`, `encryptGcmData`, `gcmDecryptData`, `listenUDP`,
`sendBroadcast`, TLS-channel APIs (`ThingNetworkApi.smali` 35-164).

**The 0x55aa frame format, session-key exchange, and LAN payload
encryption are implemented in native code** — the Python port must
reimplement them (reference: standard Tuya LAN 3.4/3.5 protocol). The
Java-visible contract is what the doc records here.

### LAN inbound — `DevTransferService.onResult(HResponse)` (1401-1574)

Native code parses frames and calls back via
`ThingNetworkInterface.OnResponseDataCallback(gwId, ThingFrame)` /
`OnResponseExceptionCallback(gwId, code, msg)` → per-gwId
`ReadResponseDataCallback` map (ThingNetworkInterface.smali 214-310).
`onResult` fans the response out to every registered
`ITransferAidlInterface.responseByBinary(devId, version, type, seq,
code, dataBinary)` (HResponse getters at 1502-1547).

### `GwTransferModel$2.responseByBinary` → `dpppdpq.onDevResponse`

`GwTransferModel$2.smali` (373-608): builds
`HResponse(devId, version, type, code, dataBinary, cid)`;
`LAN_REQUEST_GW_LOG` payloads get an extra transform + separate message;
all other frames are posted to the model handler as message type **3**.

`GwTransferModel.handleMessage` (907-1299): type 3 → log
devId/version/len/type/code → `onDevResponse(HResponse)` (1301-1415)
→ iterates `CopyOnWriteArrayList<pbqpqdq>` calling
`onDevResponse` on each registered hardware listener.

`dpppdpq.onDevResponse` (sdk/hardware/dpppdpq.smali 1504-2765) maps
`type` via `FrameTypeEnum.to(int)` and switches
(`dpppdpq$pbbppqb.smali`):

| FrameTypeEnum | Case | Handling |
|---|---|---|
| `STATUS` | 1 | `qddqppb(HResponse)` — DP report path (below) |
| `DP_QUERY_NEW` | 2 | inline DP path (pswitch_2) |
| `DP_QUERY` | 3 | same inline DP path |
| `HEART_BEAT` | 4 | no-op (heartbeat handled natively; `bdpdqbp(HResponse)` is called for all non-heartbeat frames before the switch — keeps alive/session bookkeeping) |
| `LAN_REQUEST_GW_LOG` | 5 | `IDevResponseWithoutDpDataListener.onResponse(devId, type, code==0, dataBinary)` |
| `FRM_LAN_EXT_STREAM` | 6 | `bppdpdq(HResponse)` — stream/`reqType` JSON handling (lpv≥3.4 raw string; 3.3.x `parseAesData(localKey)`; <3.3 raw) **then** `pdqppqb` forward |
| default (CONTROL, CONTROL_NEW, …) | — | `pdqppqb(HResponse)` — response-without-DP forwarder |

`pdqppqb(HResponse)` (3136-3298) → `bqqppqq` listener:
- version ≥ 3.4 → `onResponse(devId, type, code==0, dataBinary)` raw
- 3.3 ≤ version < 3.4 → `IPC_LAN_LOCAL_CONFIG` → `bdpdqbp(HResponse,
  localKey)` (GCM-style decrypt); else `ThingNetworkApi.parseAesData(
  dataBinary, localKey)`; `onResponse(..., decrypted)`
- version < 3.3 → raw `dataBinary`

#### Inline DP path (`pswitch_2`, DP_QUERY_NEW / DP_QUERY)

- `code != 0` → `bpbbqdb.onLocalDpReceivedError(devId, "11005",
  "hResponse return code != 0")`
- `code == 0` → dispatch on **lpv** (`ILocalDpMessageRespListener.getLpv(devId)`):
  - **lpv ≥ 3.4** — no decrypt: `DP_QUERY_NEW` → parse dataBinary as
    `HDpResponse` JSON; `cid` non-empty AND ≠ devId →
    `onLocalDpSubDeviceReceivedSuccess(devId, cid, ctype, dps, t)`;
    else `onLocalDpReceivedSuccess(devId, dps, t)`. Other DP_QUERY
    frames → `onLocalDpReceivedSuccess` (no cid check).
  - **3.3 ≤ lpv < 3.4** — `parseAesData(dataBinary, localKey)` first
    (native AES-ECB + version-word strip), then the same
    DP_QUERY_NEW / other split on the decrypted bytes.
  - **lpv < 3.3** — raw `HDpResponse` parse of `dataBinary`; cid check
    applies to **all** frames (sub vs ordinary callback as above).

#### STATUS report path — `qddqppb(HResponse)` (3374-3473)

`code != 0` → `onLocalDpReceivedError(devId, "11005", ...)`. Otherwise
builds `bqpbddq{dataBinary, devId, version, localKey, dedupCb}` →
`bqqbpqb` ("LocalRespManager", bqqbpqb.smali 36-270) dispatches on
`HResponse.version` (the frame's gw version, not lpv):

| version | Parser | Wire layout |
|---|---|---|
| ≥ 3.4 | `pqqqddq` ("LocalResp3_4") | 15-byte header: `ver[0:3]` ASCII, `s`=BE32@7, `o`=BE32@11; dedup `bdbdqdp.isDataUpdated(devId,s,o)` → drop "Data is Updated"; payload `dataBinary[15:]` = **plaintext JSON** `JSONObject` → `dddddqd.bdpdqbp(devId, protocol, json)` |
| ≥ 3.2 | `ppbdppp` ("LocalResp3_2") | same 15-byte header + dedup; payload `dataBinary[15:]` = `AESUtil(localKey).decryptWithBytes` (AES/ECB/PKCS5) → `HDpResponse`; null → deliver null (→ `onError`) |
| ≥ 3.1 or == "1.1" | `bdqqqpq` ("LocalResp3_1") | string: `ver(3) || sign(16 hex) || enc`; `pbbqpqd.bdpdqbp(enc, localKey)` → `HDpResponse` (null → drop); `s != -1` → dedup `isDataUpdated(devId, s)`; verify `pbbqpqd.bdpdqbp(version, encStr, localKey) == sign` else drop "The sign is invaild" |
| other | `dqbpdbq` | raw `dataBinary` → `HDpResponse`; null → deliver null |

Base `bdbbqbd.bdpdqbp(HDpResponse)` (44-66): null →
`dddddqd.onError("result data is null", ...)`; else
`dddddqd.bdpdqbp(HDpResponse)`.

Delivery — `dpppdpq$pppbppp` (the `dddddqd` callback):
- `HDpResponse.ctype == 2` AND `mbid` non-empty →
  `onLocalDpZigbeeGroupReceivedSuccess(devId, mbid, dps)`
- `cid` non-empty AND ≠ devId →
  `onLocalDpSubDeviceReceivedSuccess(devId, cid, ctype, dps, t)`
- else → `onLocalDpReceivedSuccess(devId, dps, t)`
- 3.4 plaintext channel → `onLocalDataReceived(devId, protocol, json)`
- `onError(code, msg)` → `onLocalDpReceivedError(devId, code, msg)`

### `ILocalDpMessageRespListener` — `qbdpdpp` (sdk/device)

`onLocalDpReceivedSuccess(devId, dpsJson, t)` (qbdpdpp.smali 2769-2917):
- `t != 0` → `dpsTime = {each dp key: t*1000}`; else `dpsTime = null`
- `pdppddb.bdpdqbp(devId, devId, dpsTime, dpsJson, false)` — central
  ingest (below)
- `bqbdbqb.bdpdqbp(devId, dpsJson, 1)` — stats/log hook

`onLocalDpSubDeviceReceivedSuccess(devId, cid, ctype, dpsJson, t)`
(2919-3231):
- `getSubDev(devId, cid)` → null → drop
- parse dpsJson → LinkedHashMap; `dpsTime` = `{dp: t*1000}` when `t != 0`
- `DevUtil.decodeRaw(subDevId, map)` — RAW dp decode; mutated →
  re-serialize `dpsJson`
- `DevUtil.checkReceiveCommond(subDevId, map)` → false → drop
- `pdppddb.pdqppqb(subDevId, dpsTime)` — merge dpsTime into bean
- `DevListCacheManager.updateSubDevDps(respBean, map)` — cache merge
- `bdqqbqd.bdpdqbp(devId, cid, subDevId, ctype, dpsJson, dpsTime,
  false)` → sub-device dp event
- stats `bqbdbqb.bdpdqbp(subDevId, dpsJson, 1)`

`onLocalDpReceivedError` (2733-2767) → log only. `onLocalDataReceived`
(2710-2731) → `qpbdppq.bdpdqbp(protocol, devId, json, false)` —
protocol-number-keyed local data channel.
`onLocalDpZigbeeGroupReceivedSuccess` → `qddddbd` group dispatch.

### Dedup store — `qdddqdp` ("ThingMessageCache", sdk/device)

`ILocalDpMessageRespListener.isDataUpdated` → `qbdpdpp.isDataUpdated`
(1281-1309) → `qdddqdp.bdpdqbp()` singleton. Two synchronized
`HashMap<String,Long>` stores keyed by string concat, value =
`System.currentTimeMillis()`:

- `isDataUpdated(devId, s)` — `s == -1` → **true** (always treated as
  duplicate). Key `devId+s`. Hit within 5000 ms → **remove** the key and
  return true (so a third identical message inside the window passes).
  Miss → evict-all-≥5000 ms when size > 300 (0x12c), store key→now,
  return false (qdddqdp.smali 180-227, 295-444).
- `isDataUpdated(devId, s, o)` — **`o == 0` → false immediately** (no
  dedup). Key `devId+s+o`. Same 5000 ms window + remove-on-hit;
  eviction threshold size > 900 (0x384) (qdddqdp.smali 229-293,
  446-650).

### Central DP ingest — `pdppddb.bdpdqbp(subDevId, devId, dpsTime, dpsJson, fromCloud)` (271-650)

Python port: `CentralDpIngest.ingest` in `pypopur.sdk.device_cache`.
(Note the smali checks the **second** string arg for empty and falls
back to the first; callers pass `(devId, devId, …)` or
`(devId, subDevId, …)` — effective id = arg2 if non-empty else arg1.)

Shared by MQTT and LAN inbound:

1. effective devId empty→fallback; `DevListCache.getDev` null → drop
   "Device does not exist."
2. `isSingleBle && pdqppqb(devId)` → drop "filter singleBle mqtt dp".
   `pdqppqb(String)` (1088-1144): bean null → **true**; virtual/beacon
   → false; else `DevUtil.isSingleBleLocalOnline(devId)`.
3. `hasBluetooth && fromCloud && (hasCat1 || hasWifi) &&
   pdqppqb(DeviceBean)` → drop "filter ble mqtt/lan dp".
   `pdqppqb(DeviceBean)` (933-1086): false unless
   `isSingleBleLocalOnline`; meta `ext_module_in` → false; neither
   LAN-online nor cloud-online → true; else requires
   `isBluetooth && !isSingleBle` and `communicationModes[0].type == BLE`.
4. parse `dpsJson` → LinkedHashMap; `DevUtil.decodeRaw` (RAW dps
   base64→hex, in place, returns mutated flag)
5. `DevUtil.checkReceiveCommond` → false → drop "checkReceiveCommand
   error"
6. `dpsTime` non-empty AND `bdpdqbp(devId)` (`IYuPlugin.isYuOnline`,
   plugin absent → false) AND respBean cached `dpsTime`/`dps` non-null →
   staleness filter: for each dp with incoming `t > 0`, when cached
   `t' > 0 && t' >= t` AND cached value equals incoming → remove the dp
   ("mqtt dpsTime is older than cache")
7. map empty → drop "dpMap is empty"
8. `bdpdqbp(devId, map)` (180-269) — put-all incoming entries into
   `bpbqqdq.getDps(devId)` (lazy-decoding `DeviceRespBean.dps` in-place
   merge); when that map is null the puts land in a **throwaway**
   HashMap (bean keeps null) — returns the **input** map either way
9. `pdqppqb(devId, dpsTime)` (829-931) — merge timestamps into bean
   (creates+attaches `dpsTime` when null; null input → warn + null)
10. map non-empty → if decodeRaw mutated, re-serialize `dpsJson` →
    `bdqqbqd.bdpdqbp(devId, dpsJson, fromCloud, dpsTime)` → stats hook
    (`event_sdk_instruct_dp_update`) + posts `DpUpdateEventModel(devId,
    dpsJson, isCloud){dpsTime}` (→ `ppdpppq` → `IDevListener.onDpUpdate`;
    see `11-events.md`)

### LAN discovery — `GwBroadcastMonitorModel` + `GwBroadcastMonitorService`

`GwBroadcastMonitorModel` (sdk/hardware/model) binds
`GwBroadcastMonitorService` via intent `thing.intent.action.udp`
(package `thing`); requires service version ≥ "3.0" else retries after
5000 ms (GwBroadcastMonitorModel.smali 281-369).

`GwBroadcastMonitorService` (smart/android/hardware/service):

- `buildUDPReceiver` (226-460): `addPackageCallback`, then
  `setSecurityContent(getAssetsData(ctx, "fixed_key.bmp",
  "soisiwoejre".getBytes()))` — raw asset bytes handed to the native
  lib; the file is a real 100×75 24-bit BMP (22554 B) with key material
  steganographically embedded in pixel data; `"soisiwoejre"` bytes are
  only the fallback when the asset read fails. Then `listenUDPPort()`
  and a 1000 ms `UpdateTimerTask`.
- `listenUDPPort` (1307-1344): `listenUDP(6666)`, `listenUDP(6667)`,
  `listenUDP(7000)`, then `sendBroadcastForDiscovery()`.
- `sendBroadcastForDiscovery` (599-…): payload =
  `{"ip": <local wifi ip>, "from": "app"}` UTF-8 →
  `sendBroadcast("255.255.255.255", 7000, 6000, data,
  FrameTypeEnum.APP_SEND_BROADCAST, LAN_PROTOCOL_VERSION_3_5.version, 0)`
  then repeated to the subnet broadcast address. Token saved in
  `broadcastToken`.
- `getGWBean(HgwBean)` (1146-1305): for each announcement, first evicts
  any gwMap entry with a *different* gwId but the *same* IP (stale-IP
  dedup), then `gwMap[gwId] = bean`. HgwBean carries gwId, ip, version,
  active, etc.

Python port note: replace the AIDL/service boundary with direct socket
management; `fixed_key.bmp` can be extracted from the APK and shipped
or its embedded key material pre-extracted.

### LAN-first entrypoint vs comm-pipeline

Two different entry points reach LAN:

| Path | Entry | Fallback |
|---|---|---|
| Comm pipeline (`bddqdbd`, mode LAN in `communicationModes`) | `intranetControl` → `qqdbbpp.pdqppqb` | 500 ms watchdog → `bppdpdq` (internet); LAN error → same |
| Direct model call `qqdbbpp.bdpdqbp(devId,nodeId,dps,type,logKey,cb)` (1163) | `getCommunicationOnline(LAN)` → `bpqqdpq` | `bppdpdq` wrapper → "control by server" |

The watchdog/timeout wrapper only exists in the comm-pipeline path; the
model-level path relies on hardware-layer errors.

## Subscriptions / bookkeeping

- `isSubscribe(topic)` (2780-2934): empty → true; non-`smart/mb/in/`
  prefix → true ("does not require compensation"); else `pppbppp`
  HashMap<Boolean> lookup — **miss → false**, hit → stored value.
- `subscribe([String,[I,cb)` (4512-4792): write-locked loop over
  `min(len(topics), len(qoses))`; empty topic skipped; map hit TRUE
  skipped; otherwise topic stored **FALSE** (pending) and added to the
  request lists. Empty request list → `cb.onSuccess()` immediately.
  Inner cb `$pbpdpdp.onSuccess` → each requested topic → **TRUE**;
  `onError` → passthrough, map stays FALSE.
- `unSubscribe` (4873+): `pppbppp.remove(topic)` (entry deleted, not
  set false) then client unsubscribe.
- `connect()` calls `pqdqqbd.pdqppqb().bppdpdq()` (some pre-connect
  hook) then `init()` + `pqpbdqq.connect()`.

Ported → `pypopur.sdk.mqtt_session` (`MqttServerManager`,
`SdkMqttCredentials`, `MqttConfigBean`, `init_mqtt_config`,
`mmi_flow_decrypt`, `parse_message`) and `pypopur.sdk.device_id`
(`PhoneUtil`).

## Unresolved / TBD

- `pqpbdqq` client internals (reconnect backoff, `isRealConnect`
  semantics, delivery callbacks) — only skimmed
- `pqdqqbd.pdqppqb().bppdpdq()` pre-connect hook
- MQTT-side dedup uses the same `qdddqdp` store semantics documented
  above (5000 ms window, remove-on-hit, `o==0` bypass) — confirmed:
  `qbqddpp` calls the listener's `isDataUpdated(topic, s, o)` and
  `qqpqqpq` forwards it to `qdddqdp.isDataUpdated(devId, s, o)` after
  stripping the topic prefix
- Whether `publishDevice` actually uses builder `t` (int, default -1)
  vs a fresh timestamp — `bbppbbd` sets `T=(int)System.currentTimeMillis`
  — confirm which int is the millis value vs seconds
- `PublishBean*` fastjson key order on the wire (field order:
  data, gwId, protocol, pv, sign, t — fastjson emits declaration
  order; verify against captured traffic)
- `dddpppb.bdpdqbp(devId, data)` pre-send transform detail
  (pid/subId/category_code/scene-type normalization)
- Native LAN wire format (0x55aa framing, session-key swap,
  payload AES) — inside `libnetwork-android.so`; port per standard
  Tuya LAN 3.4/3.5
