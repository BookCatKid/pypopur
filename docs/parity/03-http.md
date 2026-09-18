# 03 — HTTP transport (ATOP / Business)

Verified at opcode level against
`smali_classes3/com/thingclips/smart/android/network/`:
`ThingApiParams.smali`, `Business.smali`, `Business$RequestTask.smali`,
`request/OKHttpBusinessRequest.smali`,
`util/ThingNetGzipHelper.smali`, `util/ParseHelper.smali`,
`com/thingclips/smart/android/base/ApiParams.smali`,
`com/thingclips/sdk/device/dbppbbp.smali`.

Port: `pypopur/sdk/atop.py` (+ `pypopur/sdk/security.py` for signing).

## ApiParams/`ThingApiParams` model

`ThingApiParams.<init>(apiName, apiVersion[, region])` defaults
(345-497):
`ET_VERSION="3"`, `apiVersion` arg stored, `sessionRequire=true`,
`locationRequire=true`, `apiChannel=""`, `signWhitEncryptedBody=true`,
`downgrade=false`, `priority=0`, then `initUrlParams(region)`.

`checkAPIName` (497-577): if `apiName.startsWith("thing")` →
`apiName = ("@xx2@" + apiName).replaceAll("@xx2@thing", "smartlife")` —
i.e. **`thing.*` API names go on the wire as `smartlife.*`**.

`ApiParams` overrides (`base/ApiParams.smali`):
- `initUrlParams` puts `deviceId=PhoneUtil.getDeviceID(ctx)` into
  urlGETParams **before** super runs (so it is signed; `deviceId` is in
  the sign whitelist).
- `getSession`/`getEcode`: empty → lazy-fill from the `IBaseUser` plugin
  (`getSid`/`getEcode`) and cache on the params object.
- `getRequestBody`: super + `deviceId` again in the form body.
- `getUrlParams`: super + `lat`/`lon` when `ThingBaseSdk.locationSwitch`
  and both nonempty (else both removed).

`initUrlParams` (2242-3034) always sets: `v="*"` (overwritten by
`getUrlParams` with apiVersion), `clientId=mAppId`, `os="Android"`,
`appVersion`, `lang=ThingUtil.getLang(ctx)`, `sdkVersion`,
`deviceCoreVersion`, `ttid`, `osSystem=Build.VERSION.RELEASE`,
`requestId=UUID`, `platform=Build.MODEL`, `timeZoneId`, `et=ET_VERSION`
(+"cp=gzip" iff et=="3"), `channel=mChannel`, `appRnVersion` if set,
`bizData` = JSON of `{customDomainSupport:"1", nd?, langDebug?,
<commonParams…>, miniappVersion?, sdkInt, brand?}` (commonParams also
flattened into urlGETParams), `serverHostUrl` from
`IApiUrlProvider.getApiUrl()` / `getApiUrlByCountryCode(region)`,
`chKey = getChKey(ctx, mAppId.bytes)` when nonempty.

`getUrlParams` (1714-2217) adds at request time: `a`=rewritten apiName,
priority side-effects, `gid` when ≠0, `v`=apiVersion, `sid`+sessionRequire
when session nonempty, `isH5`/`h5Token` or removed, `sp` when spRequest,
`n4h5`, `ct`=apiChannel, PanelParams `pid`/`devId`/`uiId`, `envtag`.

## Body construction (`getPostBody`/`getRequestBody`)

`getPostBody` (1192-1275): `{postData: <string>}` or `{}`. The value is
`postData.toJSONString()` unless `signWhitEncryptedBody`, in which case
`getEncryptPostDataString()` (725-1126):

1. `requestId` from urlGETParams; generates+stores a UUID if absent.
2. `key = getEncryptoKey(requestId, sessionRequire ? ecode : null)`.
3. et `"3"`: `Base64.encodeBase64(AesGcmUtil.encryptBytes2BytesAppendNonce(
   key, postDataJson.bytes, null))` → String.
   else: `AESUtil("AES", key).encryptWithBase64(postDataJson)`
   (AES/ECB/PKCS5 → b64).
4. Any exception → `""`.

The encrypted value is the **bare base64 string** — there is no
`{"data": …}` wrapper in this build.

`getRequestBody` (1337-1490):
1. `body = getPostBody()`.
2. session nonempty → `sessionRequire=true`, `body["sid"]=session`.
3. `signMap = copy(urlParams); signMap["time"]=str(TimeStampManager.
   getCurrentTimeStamp())` (**unix seconds**, not ms — see timestamp
   note); `signMap.putAll(body)` (includes `postData` + `sid`).
4. `body["sign"] = generateSignatureSdk(signMap)` — whitelist/sort/`||`
   join; nonempty `postData` swapped to `postDataMD5Hex` **inside
   signMap only**.
5. `signMap.remove("postData")`; `body.putAll(signMap)` — so the real
   (possibly encrypted) serialized postData survives in `body` while
   every url param + `time` + `sign` is merged in.
6. `ApiParams` adds `body["deviceId"]`.

## Request (`OKHttpBusinessRequest.newOKHttpRequest`, 359-881)

- `Request.Builder`: tags (tagString, BizCallStartTime), all
  `getRequestHeaders()` headers, `x-client-trace-id: <requestId>`.
- Optional `IThingHttpServiceInterceptListener.interceptListener(a, v,
  postData)`: strips `headerParams` from batch `apis` entries, may
  rewrite `a`/`v` (apiReplace), `isPublicCloud` → ecode/headers/sid
  injection.
- `url = apiParams.getRequestUrl()` = `getUrlWithQueryString(true,
  serverHostUrl, {})` — okhttp rebuild of the host (trailing `/` added
  for empty path).
- Body: `getDataBytes()` nonnull → raw `RequestBody` with
  `MediaType.parse("audio")`; else `FormBody` over the request-body map
  (application/x-www-form-urlencoded `k=v` pairs).

## Response (`Business$RequestTask`)

`onResponse` → `lambda$onResponse$2` (764-1102):
- !2xx or null body → `handlingFailed("101", localized(httpCode))`.
- `SocketTimeoutException` → `handlingFailed("108", "read timeout")`.
- other exception (incl. decrypt/verify failures) →
  `handlingFailed("102", "json error"+apiName)`.
- else `handlingResponse(code, bodyText, url, headers)`.

`handlingResponse` (2235-2886): parse body JSON; if `sign` field nonempty
AND et ∈ {"0.0.2","3"} → `Business.decryptResponse` replaces the body
(02-security §Response verification: `sign ==
md5Lower("result="+result+"||t="+t+"||"+keyStr)` case-insensitive; et "3"
→ b64 → GCM-decrypt → gunzip iff `x-content-compress: gzip` header →
UTF-8; else AES/ECB b64 decrypt). Optional
`responseInterceptListener` may replace api name/version/response text.
Then `JSON.parseObject(body, BusinessResponse, OrderedField)` →
`onSuccessResponse`.

`handlingFailed` (2173): `BusinessResponse{errorCode=code,
errorMsg=pppbppp.bdpdqbp(ctx, msg) /* localized lookup */}` → `onFailure`.

`onSuccessResponse` (1402): success → `onSuccessResult` →
`onParser`+`onSuccess`. Failure → `onSuccessResponseWithResultFailure`
when `!isRetryMode`, else straight `onFailure`:
- `TIME_VALIDATE_FAILED` → `TimeStampManager.updateTimeStamp(t)` +
  `onRetry()`.
- `USER_SESSION_INVALID`/`USER_SESSION_LOSS` → post runnable to
  `Business.handler` (session-loss broadcast seam), errorCode rewritten
  to `"105"`, `onFailure`.
- else `onFailure`.

`onRetry` (3014): `isRetryMode=true`, `retryTime` starts at **1** and
decrements; while old value >0 → `apiParams.updateRequestId()` (new UUID)
+ `onRequest()`. Exactly **one** automatic retry; a second
`TIME_VALIDATE_FAILED` (isRetryMode now true) goes to `onFailure` as-is.

`checkApiParams` (141-457): `sessionRequire && getSession()` empty →
synthesize `BusinessResponse{errorCode="USER_SESSION_LOSS",
errorMsg="Session is not exist and need login again"}` → `onFailure`,
`SessionInvalidStat.recordHttp`, no request.

## Device API surface (`dbppbbp`)

| Method | API | ver | postData |
|---|---|---|---|
| `bdpdqbp(DpPublish,cb)` | `thing.m.device.dp.publish` | 1.0 | `{gwId, devId, dps, pcc?}` |
| `bppdpdq(devId,gwId,dps,cb)` | `thing.m.device.dp.publish` | 1.0 | `{devId, gwId, dps}` |
| `bppdpdq(devId,gwId,cb)` | `s.m.dev.dp.get` | 2.0 | `{devId, gwId}` → DpBean |
| `pbbppqb(devId,dps,cb)` | `thing.m.nb.device.dp.publish` | 1.0 | `{devId, dps}` |
| `pppbppp(gwId,devId,cb)` | `s.m.dev.dp.get` | 1.0 | `{gwId, devId}` → DpResp |

(`a::e(name,ver,k,v)` = `new ApiParams(name,ver)` + `putPostData(k,v)`;
`a::g(name,ver,sessionRequire)`; `a::f` = both.)

The `publishDps` HTTP channel (`bpppdbd` handler) and the cloud-fallback
path call `dbppbbp.bppdpdq(devId, gwId, dpsJson, cb)` — i.e.
`thing.m.device.dp.publish` v1.0 with session required.

## Statics (`ThingSmartNetWork`)

`mAppId`=clientId `aup8mma84uvgeeeayman`, `mAppSecret`=
`fg34wc8k7cfmysw9aqyvxwrkcxaqftp7`, `mChannel="sdk"` default,
`mSdkVersion`/`mDeviceCoreVersion`="6.7.0", `mTtid`, `mApiUrlProvider`
(region→host; us/eu/in map in the port), `getRequestHeaders()`,
`mCommonParams`, `envTag`, location switch + lat/lon on `ThingBaseSdk`.

## TBD / seams

- `doCommandNative` cmd-1 = HMAC-SHA256(canonical, appSecret) → hex —
  strong inference (audit §F); injectable via `ThingApiSignManager(signer=)`.
- `getEncryptoKey(requestId, null)` — NULL ecode treated as empty
  component (`GLOBAL_S + "_"`); flagged in 02-security.
- `IThingHttpServiceInterceptListener` — no impl shipped in the Popur
  app; seam not ported.
- `IApiUrlProvider` impl (per-country DNS/failover logic) — port ships
  the static region map only.
- `FusionBusiness`/`HighwayBusiness`/`QuicBusiness` alternates not ported
  (not used for device APIs).
- `Business.handler` session-loss broadcast → `on_session_invalid` seam.
