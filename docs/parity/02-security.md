# 02 — Security layer (libthing_security + crypto utils)

The app's signing/encryption is split between Java utils
(`com.thingclips.smart.android.common.utils.*`,
`com.thingclips.sdk.network.*`) and two JNI libraries loaded by
`com.thingclips.smart.security.jni.JNICLibrary` in order:
`c++_shared` → `thing_security_algorithm` → `thing_security`
(`jadx/sources/com/thingclips/smart/security/jni/JNICLibrary.java` ~113).

Native behavior below is from `popur-research/THING_SECURITY_AUDIT.md`
(ASM-verified) and the live-validated port skeleton
`popur-research/thing_security_flow.py`.

Port: `pypopur/sdk/security.py` (`ThingApiSignManager`,
`ThingNetworkSecurity`, `swap_sign_string`, `post_data_md5_hex`,
`md5_as_base64`).

## Runtime globals (native, set by command 0)

`ThingNetworkSecurity.initJNI` calls
`JNICLibrary.doCommandNative(ctx, 0, mAppSecret.getBytes(), mAppId.getBytes(), mD)`
(`smali_classes3/com/thingclips/sdk/network/ThingNetworkSecurity.smali:435-547`).

Command 0 builds `RUNTIME_GLOBAL_S` (std::string @0x384f0) as four
underscore-joined components:
`packageName + "_" + certSHA256 (uppercase, colon-separated) + "_" +
t_s.bmp-derived component + "_" + appSecret`
(THING_SECURITY_AUDIT.md §F).

For Popur App 2.0.0 this exact value is preserved in
`pypopur/popur_app2_material.py::APP2_NATIVE_MASTER_HEX` (hex of the ASCII
string). Decoded:

```
com.smartapp.popur.app_
F9:6D:61:DA:09:C6:8F:FA:AE:6E:D6:FA:D6:ED:BF:22:38:CF:3E:5D:44:50:59:4D:0B:1E:31:50:83:20:A1:DB_
5d7m7y4pwp73m3vkammx53jxmvxcjqup_
fg34wc8k7cfmysw9aqyvxwrkcxaqftp7
```

`RUNTIME_GLOBAL_C` (@0x384d8) and `RUNTIME_GLOBAL_D` (@0x38520) are also
populated by command 0 (audit §F); the audited `getChKey` output for the app
material is the 8-char value `fa44caaa` (`APP2_CH_KEY`), confirmed live
(audit "Live validation").

App-shipped constants (`jadx .../com/smartapp/popur/app/BuildConfig.java`):
`THING_SMART_APPKEY = aup8mma84uvgeeeayman` (= mAppId/clientId),
`THING_SMART_SECRET = fg34wc8k7cfmysw9aqyvxwrkcxaqftp7` (= mAppSecret).

## JNI command dispatch — `doCommandNative`

`smali_classes3/com/thingclips/sdk/network/ThingNetworkSecurity.smali:104-139`
→ `JNICLibrary.doCommandNative`. Audit §F:

- cmd 0 → init runtime globals (above).
- cmd 1 → sign: input bytes = canonical string; returns **String**
  `md5hex(md5hex(GLOBAL_S) + canonical)` — nested MD5 via the
  `hmacWrap` helper @0x12eb4 (`digestHex(concat(digestHex(GLOBAL_S), msg))`).
  Verified by direct emulation of 0x12eb4 — NOT HMAC-SHA256 (the earlier
  audit §F inference was wrong; the "HMAC-shaped" code at 0x142d8+ is a
  different path).
- cmd 2 → same `hmacWrap` over its byte[] arg (both cmds reach 0x141c8;
  they differ only in which argument slot is read).
- other cmd → null.

## Java wrappers → native calls

`ThingNetworkSecurity.smali`:

| Java | Native | Purpose |
|---|---|---|
| `computeDigest(a,b)` | `SecureNativeApi.computeDigest` | MD5(b + "\|\|" + a + "_" + GLOBAL_S) → 32 lowercase hex (audit §B) |
| `encryptPostData(key,bytes)` | `JNICLibrary.encryptPostData` | NOTE: ignores byte[] in this build; returns HMAC-derived 16-byte key material (audit §A sibling) |
| `genKey(a,b,c)` | `SecureNativeApi.genKey` | HMAC-SHA256(key=a, data=c+"_"+GLOBAL_S+"_"+nibblePermute(b)) → hex[:16] (audit §C) |
| `getChKey(ctx,bytes)` | `JNICLibrary.getChKey` | HMAC-SHA256(key=bytes, data=GLOBAL_D+"_"+GLOBAL_C) → hex64[8:16] (audit §D) |
| `getEncryptoKey(a,b)` | `JNICLibrary.getEncryptoKey` | HMAC-SHA256(key=a, data=GLOBAL_S+"_"+b) → hex64[:16] as 16 ASCII bytes (audit §A). **NULL b** (`cbz x21` @0x14d18) → data = `GLOBAL_S` alone (no underscore); non-null empty b → `GLOBAL_S + "_"`. Resolved by disasm — matches `mobile.derive_request_key` |
| `decryptResponseData(k,d)` | native @0x15774 | AES-128-GCM: key=k[:16] ASCII, nonce=d[:12], tag=d[-16:] (audit §I) |

`nibblePermute(b)`: `out[i] = b[b[i] & 0xF]` for `i < min(strlen(b),16)`
(asm @0x15188–0x151c8). For `len(b) < 16` the `b[i] & 0xF` index can read
past the string end into the NUL-padded tail of the UTF buffer — the port
mirrors this with `ljust(16, "\0")` (verified vector: `genKey("a","short","c")`
= `7e0f4f507dd6006a`).

All functions in the table above were verified byte-exact against
`libthing_security.so` via the unicorn-based JNI emulator
`popur-research/emu_jni.py` (vectors in `emu_vectors.py` and
`tests/test_native_vectors.py`). `computeDigest` uses the in-lib MD5
(`0x17ed4`/`0x17ef0`/`0x18a5c`, standard IV @0x72d0); `getEncryptoKey`,
`genKey`, `encryptPostData` and `getChKey` use HMAC-SHA256 via the
`0x16d08`/`0x16fa4` descriptor path (hash id 6).

## Request signing — `ThingApiSignManager`

`smali_classes3/com/thingclips/sdk/network/ThingApiSignManager.smali`

Whitelist (`<clinit>` lines 21-125, order = array order, NOT sorted order):

```
a, v, lat, lon, lang, deviceId, appVersion, ttid, isH5, h5Token,
os, clientId, postData, time, requestId, et, n4h5, sid, chKey, sp
```

`generateSignatureSdk(map)` (167-472):

1. Copy keySet → `LinkedList`, `Collections.sort` (lexicographic ASCII).
2. For each sorted key: skip if not in whitelist; skip if value empty.
3. If key == `postData` and value nonempty: replace map value IN PLACE with
   `postDataMD5Hex(value)` (see below) — mutation visible to caller.
4. Join `k=v` pairs with `||` separator.
5. `pbddddb.bdpdqbp().bdpdqbp(joined)` → `doCommandNative(ctx, 1, bytes,
   null, mD)` → returned String is the `sign` field.
   (`pbddddb.smali:92-121`)

`postDataMD5Hex(s)` (1058-1099) = `swapSignString(md5hex_lower(s))`.

`swapSignString(h)` (1101-1201) for 32-char `h`:
`h[8:16] + h[0:8] + h[24:32] + h[16:24]` — the classic Tuya MD5 reorder.

`getRequestKeyBySorted(map)` (474-...): same sort+join but NO whitelist and
no postData swap, then `md5AsBase64(joined)` (MD5→lower hex) — used for
dedup/request keys, not for `sign`.

`getUrlWithQueryString(addQuery, base, map)` (671-...): URL builder helper;
`%20` for spaces.

## MD5/hex encoding notes

`MD5Util.md5AsBase64(String)` (MD5Util.smali:362-383) is **misnamed**: it
returns `HexUtil.bytesToHexString(md5bytes)` = **lowercase hex** via
`Integer.toHexString` with manual 0-padding (HexUtil.smali:89-160+;
`hexString` field "0123456789ABCDEF" is used by other methods, not this one).

`MD5Util.md5AsBase64For16(s)` (400-...) = `md5AsBase64(s)[8:24]` — 16-char
middle slice.

## RSA login encryption — `RSAUtil`

`smali_classes3/com/thingclips/smart/android/common/utils/RSAUtil.smali`

- `generateRSAPublicKey(prefix, "modulus\nexponent")` (368-435): splits the
  string on lines, `BigInteger(line1)`, `BigInteger(line2)` →
  `RSAPublicKeySpec` via `KeyFactory.getInstance(prefix-or-"RSA")`;
  **side effect: stores in static field `RSAUtil.pubKey`**.
- `encrypt(transformation, plaintext)` (166-186): encrypts
  `plaintext.getBytes()` with static `pubKey` via
  `Cipher.getInstance("RSA/NONE/PKCS1Padding")` initialized with
  **`FixedSecureRandom`** → returns `HexUtil.bytesToHexString` (**lowercase
  hex** of the ciphertext).
- `FixedSecureRandom` (FixedSecureRandom.smali:15-135): `nextBytes` fills
  output with repeating 20-byte seed
  `aa fd 12 f6 59 ca e6 34 89 b4 79 e5 07 6d de c2 f0 6c b5 8f`
  → PKCS1 v1.5 padding bytes are deterministic → identical input+key yields
  identical ciphertext (enables exact test vectors).
- KEY_SIZE = 0x200 (512-bit modulus expected from token endpoint).

## AES-GCM — `AesGcmUtil`

`smali_classes3/com/thingclips/smart/android/common/utils/AesGcmUtil.smali`

- `generateRandomNonce()` (305-364): 12 bytes, `SecureRandom.getInstanceStrong`
  fallback `new SecureRandom()`.
- `encryptBytes2BytesAppendNonce(key, pt, aad)` (243-303):
  `nonce(12) || AES-128-GCM(key, nonce, pt, aad)`.ct||tag` — nonce prepended.
- `decryptBytesAppendedNonce2Bytes(key, blob, aad)` (111-...): splits
  nonce(12) prefix, GCM decrypt.

## Response verification — `Business`

`smali_classes3/com/thingclips/smart/android/network/Business.smali`

- `decryptResponse(params, body, headers)` (2720-3042):
  1. `requestId` from params urlParams (must be nonempty).
  2. Parse body as `BusinessEncryptResponse` (fields `result`, `sign`, `t`;
     OrderedField feature).
  3. `key = getEncryptoKey(requestId, sessionRequire ? ecode : null)`.
  4. `verifyResponseResult(keyStr, resp)` (1913-2041):
     `sign == md5Hex("result=" + result + "||t=" + t + "||" + keyStr)`
     case-insensitive; else RuntimeException "verify response result failed".
  5. et=="3": `Base64.decode(result)` →
     `AesGcmUtil.decryptBytesAppendedNonce2Bytes(key, blob, null)` →
     `ThingNetGzipHelper.unzipDecryptData` (cp=gzip → gunzip) →
     `ParseHelper.responseByteToString`.
  6. else: `AESUtil("AES").setKeyValue(key).decryptWithBase64(result)`
     (AES-ECB path for et 0.0.1/0.0.2).

- `handlingResponse` (`Business$RequestTask.smali:2235-2390`): decrypt is only
  attempted when the response JSON contains a `sign` field AND
  et ∈ {"0.0.2","3"}; otherwise body parsed as plaintext JSON.

## Still open

- `getConfig`/`t_cdc.tcfg` provisioning of GLOBAL_C/GLOBAL_D (audit §E) —
  for the library port we ship the resolved constants; the provisioning path
  itself is not needed at runtime.
- `doCommandNative` cmd 0's Context/assets/cert chain **re-emulated
  end-to-end** in `popur-research/emu_cmd0.py` (Unicorn + JNI stubs):
  `Context.getAssets` → `AAssetManager_open("t_s.bmp")` →
  `read_keys_from_content` (native, `libthing_security_algorithm.so`) parses
  the BMP steganography — Java-`hashCode(appId)` picks a pixel index into the
  `0x36`-offset pixel data, extracts a hex key — → hex-decode →
  `Context.getPackageManager().getPackageInfo().signatures[0].toByteArray()` →
  `CertificateFactory.generateCertificate` → `cert.getEncoded()` →
  `MessageDigest.digest` (SHA-256) → colon-hex. Result:
  `GLOBAL_D = "com.smartapp.popur.app"`,
  `GLOBAL_C = "F9:6D:61:DA:…:A1:DB"`,
  `GLOBAL_S = D + "_" + C + "_" + keyMaterial + "_" + appSecret`
  = `…_5d7m7y4pwp73m3vkammx53jxmvxcjqup_…` — byte-exact equal to the shipped
  `APP2_NATIVE_MASTER_HEX`. The decoded-key vector lands in the global at
  `0x384c0`.
- `encryptPostData` native ignores its byte[] — the actual POST encryption is
  Java-side AES-GCM above.
