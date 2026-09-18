# 06 — Auth / login flow

## App call site

`ThingHomeSdk.getUserInstance().loginWithEmail(countryCode, email, password, cb)`
→ `com.thingclips.sdk.user.qpppdqb.loginWithEmail` (smali 1146-1160)
→ `dqdbbqp.pdqppqb(...)`.

## Sequence (`dqdbbqp.smali:1325-1370`)

1. Internal validation of email/password/callback; abort on fail.
2. Build token callback (`dqdbbqp$bdpdqbp.smali`).
3. Request token: `pqdbppq.bdpdqbp(countryCode, email, isUid=false,
   server="", callback)` → `pqdbppq.smali:1310-1377`:
   - `a = thing.m.user.username.token.get`, `v = 2.0`
   - `sessionRequire(false)`
   - postData: `countryCode`, `username`, `isUid`, opt `server`
   - result bean: `TokenBean` { `publicKey`, `exponent`, `token`,
     `ifencrypt` }.
4. On token success (`dqdbbqp$bdpdqbp`):
   - `RSAUtil.generateRSAPublicKey` on `publicKey + "\n" + exponent`
     (stores static `pubKey`; BigInteger modulus/exponent).
   - `passwd = RSAUtil.encrypt("RSA/NONE/PKCS1Padding", password)` →
     lowercase hex ciphertext, deterministic (FixedSecureRandom, §02).
   - Final login call with token + encrypted passwd.
5. On token failure: forward `BusinessResponse.errorCode`/`errorMsg`.

## Final login API (`pqdbppq.smali:3041-3107`)

- `a = thing.m.user.email.password.login`, `v = 3.0`
- `sessionRequire(false)`
- postData: `countryCode`, `email`, `passwd` (RSA hex),
  `options = "{\"group\": 1}"`, `token`, `ifencrypt` (int flag).
- Result bean: `User` (contains `sid`/`ecode`/uid etc.).

## Sibling APIs (same pattern, for completeness)

- `thing.m.user.uid.password.login.reg` v1.0: postData `countryCode`,
  `uid`, `passwd`, `token`, `ifencrypt`, `createGroup`,
  `options={"group":1}`; sessionRequire(false).
- `thing.m.user.mobile.passwd.login` v3.0: `countryCode`, `mobile`,
  `passwd`, `options={"group":1}`, `token`, `ifencrypt`; sessionRequire(false).
- `thing.m.user.username.mfa.code.get` — MFA branch.
- Registration/reset: `thing.m.user.email.register`,
  `thing.m.user.email.password.reset`, `thing.m.user.email.bind.code.send`.

## Session state after login

- `User` bean → `IBaseUser` plugin; `ApiParams.getSession/getEcode` pull
  `sid`/`ecode` lazily at request time (03-http §ApiParams).
- `ifencrypt` from TokenBean controls whether `ecode` is used in
  `getEncryptoKey(requestId, ecode)` for response decryption (03-http
  §Response; 02-security `getEncryptoKey`).

## Error propagation

- Token step failure: `errorCode`/`errorMsg` forwarded as-is.
- Login step failure: same.
- Validation failure: callback error before any network call.

## TBD

- Exact `User`/`TokenBean` field lists (beans smali).
- Whether the app persists `User` to SharedPreferences (user storage impl).
- `ifencrypt` semantics in detail (0/1 → ecode participation).
