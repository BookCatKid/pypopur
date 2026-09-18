"""Port of the ATOP HTTP transport.

Java references (smali_classes3):
- ``com.thingclips.smart.android.network.ThingApiParams`` /
  ``com.thingclips.smart.android.base.ApiParams`` — request parameter model.
- ``com.thingclips.smart.android.network.Business$RequestTask`` +
  ``Business`` — request lifecycle, response decrypt/verify, error
  classification, retry.
- ``com.thingclips.smart.android.network.request.OKHttpBusinessRequest`` —
  request construction (headers, ``x-client-trace-id``, intercept hook,
  urlencoded form body vs raw ``dataBytes`` body).
- ``com.thingclips.sdk.device.dbppbbp`` — device API surface
  (``thing.m.device.dp.publish`` et al).
- ``com.thingclips.smart.android.network.ThingSmartNetWork`` — statics
  (modeled here as :class:`NetworkStatics`).

Wire quirks reproduced:

- ``checkAPIName`` rewrites API names starting with ``thing`` to
  ``smartlife.*`` (``"@xx2@" + name`` then ``replaceAll("@xx2@thing",
  "smartlife")``).
- ``getRequestBody`` merges urlParams + ``time`` + postBody, signs the
  merged map (postData swapped to its MD5 reorder inside the sign map
  only), then drops ``postData`` from the merged copy so the real
  (possibly encrypted) serialized postData survives in the form body.
- ``signWhitEncryptedBody`` (default true): postData is replaced by
  ``b64(AES-128-GCM(getEncryptoKey(requestId, ecode?), postDataJson))``
  for et ``"3"``, else AES/ECB base64.
- Encrypted responses are only attempted when the body has a ``sign``
  field AND et ∈ {"0.0.2", "3"}; otherwise parsed as plaintext.
- ``TIME_VALIDATE_FAILED`` syncs ``TimeStampManager`` and retries ONCE
  (``retryTime`` starts at 1); ``USER_SESSION_INVALID``/
  ``USER_SESSION_LOSS`` are remapped to errorCode ``"105"``.
- Transport failures: HTTP !2xx or null body → ``"101"``;
  SocketTimeout → ``"108"``; parse/decrypt exceptions → ``"102"``.
"""

from __future__ import annotations

import gzip
import json
import uuid
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from ._fastjson import to_json_string
from ._java import text_is_empty
from .crypto import (
    AESUtil,
    base64_decode,
    base64_encode,
    gcm_decrypt_appended_nonce,
    gcm_encrypt_appended_nonce,
)
from .security import ThingApiSignManager, ThingNetworkSecurity, md5_as_base64
from .timestamp import TimeStampManager

#: Region host table (``IApiUrlProvider.getApiUrlByCountryCode``).
REGION_HOSTS = {
    "us": "https://a1-us.iotbing.com",
    "eu": "https://a1.tuyaeu.com",
    "in": "https://a1-in.iotbing.com",
}

#: Error codes synthesized by ``Business$RequestTask``.
ERR_RESPONSE_NULL = "101"
ERR_JSON_OR_DECRYPT = "102"
ERR_SESSION_LOSS = "105"
ERR_READ_TIMEOUT = "108"
ERR_SESSION_NOT_EXIST = "USER_SESSION_LOSS"

_ET_AES_GCM = "3"
_ET_AES_GCM_OLD = "0.0.2"


class ApiUrlProvider(Protocol):
    """``IApiUrlProvider`` — region host resolution."""

    def get_api_url(self) -> str: ...

    def get_api_url_by_country_code(self, code: str) -> str: ...


class StaticApiUrlProvider:
    """Region-map provider; unknown codes fall back to the default host."""

    def __init__(self, default_region: str = "us", hosts: Mapping[str, str] | None = None) -> None:
        self._hosts = dict(hosts or REGION_HOSTS)
        self._default = self._hosts[default_region]

    def get_api_url(self) -> str:
        return self._default

    def get_api_url_by_country_code(self, code: str) -> str:
        return self._hosts.get(code, self._default)


class UserSession(Protocol):
    """``IBaseUser`` — lazy sid/ecode source for ``ApiParams``."""

    def get_sid(self) -> str | None: ...

    def get_ecode(self) -> str | None: ...


class NetworkStatics:
    """Port of the ``ThingSmartNetWork`` static fields the transport reads.

    ``headers`` stands in for ``getRequestHeaders()``; ``user`` for the
    ``IBaseUser`` plugin; ``location_switch``/``latitude``/``longitude``
    for ``ThingBaseSdk`` location state.

    ``app_secret`` (``mAppSecret`` in Java) is only consumed by the native
    cmd-0 provisioning that builds ``RUNTIME_GLOBAL_S``; this port skips
    cmd-0, so pass the resolved GLOBAL_S master here — it is handed to
    :class:`ThingApiSignManager` as the cmd-1 HMAC key material.
    """

    def __init__(
        self,
        *,
        app_id: str,
        app_secret: str | bytes,
        app_version: str,
        sdk_version: str,
        device_core_version: str,
        ttid: str,
        lang: str,
        os_system: str,
        platform: str,
        time_zone_id: str,
        ch_key: str,
        device_id: str,
        api_url_provider: ApiUrlProvider | None = None,
        channel: str = "sdk",
        common_params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        user: UserSession | None = None,
        sdk_int: str = "",
        brand: str = "",
        app_rn_version: str = "",
        mini_app_version: str = "",
        neutral_domain_switch: bool = False,
        lang_debug: bool = False,
        env_tag: str = "",
        location_switch: bool = False,
        latitude: str = "",
        longitude: str = "",
    ) -> None:
        self.app_id = app_id
        self.app_secret = app_secret
        self.app_version = app_version
        self.sdk_version = sdk_version
        self.device_core_version = device_core_version
        self.ttid = ttid
        self.lang = lang
        self.os_system = os_system
        self.platform = platform
        self.time_zone_id = time_zone_id
        self.ch_key = ch_key
        self.device_id = device_id
        self.api_url_provider = api_url_provider or StaticApiUrlProvider()
        self.channel = channel
        self.common_params = dict(common_params or {})
        self.headers = dict(headers or {})
        self.user = user
        self.sdk_int = sdk_int
        self.brand = brand
        self.app_rn_version = app_rn_version
        self.mini_app_version = mini_app_version
        self.neutral_domain_switch = neutral_domain_switch
        self.lang_debug = lang_debug
        self.env_tag = env_tag
        self.location_switch = location_switch
        self.latitude = latitude
        self.longitude = longitude


def _check_api_name(api_name: str) -> str:
    """``ThingApiParams.checkAPIName`` — ``thing.*`` becomes
    ``smartlife.*`` on the wire."""

    if api_name.startswith("thing"):
        return ("@xx2@" + api_name).replace("@xx2@thing", "smartlife")
    return api_name


class ThingApiParams:
    """Port of ``ThingApiParams`` + the ``ApiParams`` overrides.

    The two Java classes are merged; the ``ApiParams`` behaviors
    (deviceId url param, lazy sid/ecode, lat/lon) apply when ``net`` is a
    full :class:`NetworkStatics` — i.e. always in this port.
    """

    def __init__(
        self,
        api_name: str,
        api_version: str,
        net: NetworkStatics,
        *,
        security: ThingNetworkSecurity | None = None,
        region: str | None = None,
        timestamp: TimeStampManager | None = None,
        signer: ThingApiSignManager | None = None,
    ) -> None:
        self.net = net
        self.security = security
        self.signer = signer or ThingApiSignManager(net.app_secret)
        self.timestamp = timestamp or TimeStampManager()
        # ctor defaults (ThingApiParams.<init>)
        self.et_version = "3"
        self.url_get_params: dict[str, str] = {}
        self.api_version = api_version
        self.session_require = True
        self.location_require = True
        self.is_h5_request = False
        self.is_n4h5_request = False
        self.api_channel = ""
        self.sign_with_encrypted_body = True
        self.downgrade = False
        self.priority = 0
        self.sp_request = False
        self.gid = 0
        self.h5_token: str | None = None
        self.ecode: str | None = None
        self.session: str | None = None
        self.post_data: dict | None = None
        self.data_bytes: bytes | None = None
        self.http_method = "POST"
        self.request_time = 0
        self.response_time = 0
        self.server_host_url = ""
        self.api_name = api_name
        self.init_url_params(region)

    # -- construction ----------------------------------------------------

    def _check_api_name(self) -> None:
        self.api_name = _check_api_name(self.api_name)

    def init_url_params(self, region: str | None) -> None:
        """``ApiParams.initUrlParams`` + ``ThingApiParams.initUrlParams``."""

        self.url_get_params["deviceId"] = self.net.device_id
        self._check_api_name()
        p = self.url_get_params
        net = self.net
        p["v"] = "*"
        p["clientId"] = net.app_id
        p["os"] = "Android"
        p["appVersion"] = net.app_version
        p["lang"] = net.lang
        p["sdkVersion"] = net.sdk_version
        p["deviceCoreVersion"] = net.device_core_version
        p["ttid"] = net.ttid
        p["osSystem"] = net.os_system
        p["requestId"] = str(uuid.uuid4())
        p["platform"] = net.platform
        p["timeZoneId"] = net.time_zone_id
        p["et"] = self.et_version
        if self.et_version == _ET_AES_GCM:
            p["cp"] = "gzip"
        p["channel"] = net.channel
        if not text_is_empty(net.app_rn_version):
            p["appRnVersion"] = net.app_rn_version
        biz: dict[str, Any] = {"customDomainSupport": "1"}
        if net.neutral_domain_switch:
            p["nd"] = "1"
            biz["nd"] = "1"
        if net.lang_debug:
            p["langDebug"] = "true"
            biz["langDebug"] = True
        if net.common_params:
            biz.update(net.common_params)
            for k, v in net.common_params.items():
                p[k] = str(v)
        if not text_is_empty(net.mini_app_version):
            biz["miniappVersion"] = net.mini_app_version
        biz["sdkInt"] = net.sdk_int
        if not text_is_empty(net.brand):
            biz["brand"] = net.brand
        p["bizData"] = to_json_string(biz)
        provider = net.api_url_provider
        self.server_host_url = (
            provider.get_api_url()
            if text_is_empty(region)
            else provider.get_api_url_by_country_code(region)
        )
        if not text_is_empty(net.ch_key):
            p["chKey"] = net.ch_key

    # -- accessors -------------------------------------------------------

    def has_post_data(self) -> bool:
        return self.post_data is not None

    def put_post_data(self, key: str, value: Any) -> ThingApiParams:
        if self.post_data is None:
            self.post_data = {}
        self.post_data[key] = value
        return self

    def get_post_data_string(self) -> str:
        return to_json_string(self.post_data) if self.post_data is not None else ""

    def get_session(self) -> str | None:
        """``ApiParams.getSession`` — lazy-fill from the user plugin."""
        if text_is_empty(self.session) and self.net.user is not None:
            sid = self.net.user.get_sid()
            if sid:
                self.session = sid
        return self.session

    def get_ecode(self) -> str | None:
        """``ApiParams.getEcode`` — lazy-fill from the user plugin."""
        if text_is_empty(self.ecode) and self.net.user is not None:
            ecode = self.net.user.get_ecode()
            if ecode:
                self.ecode = ecode
        return self.ecode

    def get_url_params(self) -> dict[str, str]:
        """``ThingApiParams.getUrlParams`` + ``ApiParams`` lat/lon."""
        out = dict(self.url_get_params)
        out["a"] = self.api_name
        if self.gid != 0:
            out["gid"] = str(self.gid)
        out["v"] = self.api_version
        session = self.get_session()
        if not text_is_empty(session):
            out["sid"] = session
            self.session_require = True
        if self.is_h5_request:
            out["isH5"] = "1"
            out["h5Token"] = self.h5_token or ""
        else:
            out.pop("isH5", None)
            out.pop("h5Token", None)
        if self.sp_request:
            out["sp"] = "1"
        else:
            out.pop("sp", None)
        if self.is_n4h5_request:
            out["n4h5"] = "1"
        else:
            out.pop("n4h5", None)
        if not text_is_empty(self.api_channel):
            out["ct"] = self.api_channel
        if not text_is_empty(self.net.env_tag):
            out["envtag"] = self.net.env_tag
        if self.net.location_switch:
            lat, lon = self.net.latitude, self.net.longitude
            if not text_is_empty(lat) and not text_is_empty(lon):
                out["lat"] = lat
                out["lon"] = lon
            else:
                out.pop("lat", None)
                out.pop("lon", None)
        return out

    def update_request_id(self) -> None:
        self.url_get_params["requestId"] = str(uuid.uuid4())

    # -- body ------------------------------------------------------------

    def get_encrypt_post_data_string(self) -> str:
        """``getEncryptPostDataString``: key =
        ``getEncryptoKey(requestId, sessionRequire ? ecode : null)``;
        et ``"3"`` → b64(GCM-nonce-append(postDataJson)), else AES/ECB b64.
        Exceptions → ``""``."""

        if not self.has_post_data():
            return ""
        request_id = self.url_get_params.get("requestId")
        if text_is_empty(request_id):
            request_id = str(uuid.uuid4())
            self.url_get_params["requestId"] = request_id
        ecode = self.get_ecode() if self.session_require else None
        try:
            key = self.security.get_encrypto_key(request_id, ecode)
            plain = self.get_post_data_string()
            if _ET_AES_GCM == self.et_version:
                blob = gcm_encrypt_appended_nonce(key, plain.encode(), None)
                return base64_encode(blob).decode()
            return AESUtil(key).encrypt_with_base64(plain)
        except Exception:
            return ""

    def get_post_body(self) -> dict[str, str]:
        """``getPostBody``: ``{postData: <serialized-or-encrypted>}``."""
        body: dict[str, str] = {}
        if self.has_post_data():
            if self.sign_with_encrypted_body:
                body["postData"] = self.get_encrypt_post_data_string()
                return body
            body["postData"] = self.get_post_data_string()
        return body

    def get_request_body(self) -> dict[str, str]:
        """``ApiParams.getRequestBody`` — merged form map (see module doc)."""

        body = self.get_post_body()
        session = self.get_session()
        if not text_is_empty(session):
            self.session_require = True
            body["sid"] = session
        sign_map: dict[str, str] = dict(self.get_url_params())
        sign_map["time"] = str(self.timestamp.get_current_timestamp())
        sign_map.update(body)
        body["sign"] = self.signer.generate_signature_sdk(sign_map)
        sign_map.pop("postData", None)
        body.update(sign_map)
        body["deviceId"] = self.net.device_id
        return body

    def get_request_url(self) -> str:
        """``getRequestUrl``: okhttp rebuild of the host; empty query map
        leaves ``<host>/`` (HttpUrl.Builder adds the trailing slash)."""

        base = self.server_host_url
        if base is None:
            return None  # type: ignore[return-value]
        base = base.replace(" ", "%20")
        # Rebuild as okhttp does: keep scheme+host+path, ensure trailing /.
        if not base.endswith("/") and "?" not in base:
            base += "/"
        return base


class BusinessResponse:
    """``BusinessResponse`` / ``BusinessEncryptResponse`` merged view."""

    def __init__(self, raw: Mapping[str, Any] | None = None) -> None:
        raw = raw or {}
        self.success = bool(raw.get("success", False))
        self.api = raw.get("a") or raw.get("api")
        self.v = raw.get("v")
        self.error_code = raw.get("errorCode")
        self.error_msg = raw.get("errorMsg")
        self.result = raw.get("result")
        self.t = raw.get("t")
        self.status = raw.get("status")
        self.sign = raw.get("sign")

    def is_success(self) -> bool:
        return self.success

    def get_timestamp(self) -> int:
        try:
            return int(self.t)
        except (TypeError, ValueError):
            return 0


#: ``http_post(url, headers, form) -> (status, body_text, headers_list)``
#: where ``headers_list`` is ``[(name, value), ...]`` — injectable seam for
#: OkHttp.
HttpPost = Callable[
    [str, Mapping[str, str], Mapping[str, str]], "tuple[int, str | None, list[tuple[str, str]]]"
]


class Business:
    """Synchronous port of ``Business`` + ``Business$RequestTask``.

    ``asyncRequest`` maps to :meth:`request` with a ``ResultListener``;
    there is no executor in this port — the OkHttp callback boundaries are
    flattened to a straight-line call.
    """

    def __init__(
        self,
        net: NetworkStatics,
        *,
        security: ThingNetworkSecurity,
        http_post: HttpPost | None = None,
        timestamp: TimeStampManager | None = None,
        signer: ThingApiSignManager | None = None,
        on_session_invalid: Callable[[BusinessResponse], None] | None = None,
        localize_error: Callable[[str], str] | None = None,
    ) -> None:
        self.net = net
        self.security = security
        self.http_post = http_post
        self.timestamp = timestamp or TimeStampManager()
        self.signer = signer or ThingApiSignManager(net.app_secret)
        self.on_session_invalid = on_session_invalid
        # ``pppbppp.bdpdqbp(ctx, msg)`` — localized error text; identity by default.
        self.localize_error = localize_error or (lambda msg: msg)

    # -- public API ------------------------------------------------------

    def new_api_params(
        self, api_name: str, api_version: str, region: str | None = None
    ) -> ThingApiParams:
        return ThingApiParams(
            api_name,
            api_version,
            self.net,
            security=self.security,
            region=region,
            timestamp=self.timestamp,
            signer=self.signer,
        )

    def request(self, params: ThingApiParams) -> BusinessResult:
        """Run one ``RequestTask`` end-to-end; returns the result the
        ``ResultListener`` would have received."""

        result = BusinessResult()
        retry_mode = False
        while True:
            # checkApiParams — session refetched from the user plugin.
            if params.session_require and text_is_empty(params.get_session()):
                resp = BusinessResponse()
                resp.api = params.api_name
                resp.v = params.api_version
                resp.error_msg = "Session is not exist and need login again"
                resp.error_code = ERR_SESSION_NOT_EXIST
                result.failure(resp, params.api_name)
                return result
            resp = self._request_once(params)
            if resp.is_success():
                result.success(resp, resp.api)
                return result
            if not retry_mode and resp.error_code == "TIME_VALIDATE_FAILED":
                # onSuccessResponseWithResultFailure → onRetry:
                # retryTime 1→0 permits exactly one re-request.
                self.timestamp.update_timestamp(resp.get_timestamp())
                params.update_request_id()
                retry_mode = True
                continue
            # retry mode or ordinary failure → onFailure.
            if resp.error_code in ("USER_SESSION_INVALID", "USER_SESSION_LOSS"):
                if self.on_session_invalid:
                    self.on_session_invalid(resp)
                resp.error_code = ERR_SESSION_LOSS
            result.failure(resp, resp.api)
            return result

    # -- internals -------------------------------------------------------

    def _request_once(self, params: ThingApiParams) -> Any:
        """``requestByOkhttp`` + ``onResponse``; returns ``"retry"``, a
        ``BusinessResponse``, or a pre-failed ``BusinessResult`` marker."""

        if self.http_post is None:
            raise RuntimeError("http_post seam not configured")
        try:
            body = params.get_request_body()
            url = params.get_request_url()
            headers = dict(self.net.headers)
            headers["x-client-trace-id"] = params.url_get_params.get("requestId", "")
            status, text, resp_headers = self.http_post(url, headers, body)
        except TimeoutError:
            return self._handling_failed(ERR_READ_TIMEOUT, "read timeout", params)
        except Exception:
            return self._handling_failed(
                ERR_JSON_OR_DECRYPT, f"json error{params.api_name}", params
            )
        if not (200 <= status < 300) or text is None:
            return self._handling_failed(ERR_RESPONSE_NULL, str(status), params)
        # handlingResponse
        try:
            body_text = text
            parsed = json.loads(text)
            if not text_is_empty(parsed.get("sign") if isinstance(parsed, dict) else None) and (
                params.et_version in (_ET_AES_GCM_OLD, _ET_AES_GCM)
            ):
                body_text = self.decrypt_response(params, text, resp_headers)
            resp = BusinessResponse(json.loads(body_text))
        except Exception:
            return self._handling_failed(
                ERR_JSON_OR_DECRYPT, f"json error{params.api_name}", params
            )
        return resp

    def _handling_failed(self, code: str, msg: str, params: ThingApiParams) -> BusinessResponse:
        """``handlingFailed`` — errorMsg goes through the localized
        ``pppbppp.bdpdqbp(ctx, msg)`` lookup."""

        resp = BusinessResponse()
        resp.error_code = code
        resp.error_msg = self.localize_error(msg)
        resp.api = params.api_name
        return resp

    # -- decrypt/verify --------------------------------------------------

    def decrypt_response(
        self,
        params: ThingApiParams,
        body: str,
        resp_headers: list[tuple[str, str]],
    ) -> str:
        """``Business.decryptResponse`` (2720-3042)."""

        request_id = params.get_url_params().get("requestId")
        if text_is_empty(request_id):
            raise ValueError("requestId is null")
        resp = BusinessResponse(json.loads(body))
        ecode = params.get_ecode() if params.session_require else None
        key = self.security.get_encrypto_key(request_id, ecode)
        key_str = key.decode()
        # verifyResponseResult — equalsIgnoreCase(md5AsBase64(expected)).
        expected = f"result={resp.result}||t={resp.t}||{key_str}"
        md5 = md5_as_base64(expected)
        if text_is_empty(expected) or text_is_empty(md5) or not (resp.sign or "").lower() == md5:
            raise RuntimeError("verify response result failed")
        if params.et_version == _ET_AES_GCM:
            blob = base64_decode(resp.result.encode())
            plain = gcm_decrypt_appended_nonce(key, blob, None)
            if _is_gzip(resp_headers):
                plain = gzip.decompress(plain)
            return plain.decode("utf-8")
        return AESUtil(key).decrypt_with_base64(resp.result)


def _is_gzip(resp_headers: list[tuple[str, str]]) -> bool:
    """``ThingNetGzipHelper.isGzip`` — header ``x-content-compress: gzip``."""

    for k, v in resp_headers:
        if k.lower() == "x-content-compress" and v.lower() == "gzip":
            return True
    return False


class BusinessResult:
    """Result container mirroring the ``ResultListener`` callback pair."""

    def __init__(self) -> None:
        self.response: BusinessResponse | None = None
        self.data: Any = None
        self.api_name: str | None = None
        self.succeeded = False

    def success(self, resp: BusinessResponse, api_name: str | None) -> None:
        self.response = resp
        self.data = resp.result
        self.api_name = api_name
        self.succeeded = True

    def failure(self, resp: BusinessResponse, api_name: str | None) -> None:
        self.response = resp
        self.api_name = api_name
        self.succeeded = False


class DeviceApi:
    """Port of ``com.thingclips.sdk.device.dbppbbp`` (DP subset)."""

    API_DP_PUBLISH = "thing.m.device.dp.publish"
    API_NB_DP_PUBLISH = "thing.m.nb.device.dp.publish"
    API_DP_GET = "s.m.dev.dp.get"

    def __init__(self, business: Business) -> None:
        self.business = business

    def publish_dps(self, dev_id: str, gw_id: str, dps: str, pcc: str = "") -> BusinessResult:
        """``bppdpdq(devId, gwId, dps, cb)`` —
        ``thing.m.device.dp.publish`` v1.0; postData
        ``{devId, gwId, dps, pcc?}`` (insertion order: devId first via the
        ``a::e`` helper, then gwId, dps, pcc)."""

        params = self.business.new_api_params(self.API_DP_PUBLISH, "1.0")
        params.put_post_data("devId", dev_id)
        params.put_post_data("gwId", gw_id)
        params.put_post_data("dps", dps)
        if not text_is_empty(pcc):
            params.put_post_data("pcc", pcc)
        return self.business.request(params)

    def publish_dp_bean(self, pub) -> BusinessResult:
        """``bdpdqbp(DpPublish, cb)`` — same API/version but postData order
        ``{gwId, devId, dps, pcc?}`` (DpPublish getter order)."""

        params = self.business.new_api_params(self.API_DP_PUBLISH, "1.0")
        params.put_post_data("gwId", pub.gw_id)
        params.put_post_data("devId", pub.dev_id)
        params.put_post_data("dps", pub.dps)
        if not text_is_empty(pub.pcc):
            params.put_post_data("pcc", pub.pcc)
        return self.business.request(params)

    def atop_publish(self, pub, cb) -> None:
        """Adapter for the ``DevCloudControl.atop_publish`` seam —
        ``DpPublish`` in, ``ResultCallback``-shaped ``cb`` out."""

        res = self.publish_dp_bean(pub)
        if cb is None:
            return
        if res.succeeded:
            cb.on_success()
        else:
            resp = res.response
            cb.on_error(resp.error_code, resp.error_msg)

    def publish_dps_nb(self, dev_id: str, dps: str) -> BusinessResult:
        """``pbbppqb(devId, dps, cb)`` — ``thing.m.nb.device.dp.publish``
        v1.0; postData ``{devId, dps}``."""

        params = self.business.new_api_params(self.API_NB_DP_PUBLISH, "1.0")
        params.put_post_data("devId", dev_id)
        params.put_post_data("dps", dps)
        return self.business.request(params)

    def get_dps_v2(self, dev_id: str, gw_id: str) -> BusinessResult:
        """``bppdpdq(devId, gwId, cb)`` — ``s.m.dev.dp.get`` v2.0 → DpBean;
        postData ``{devId, gwId}``."""

        params = self.business.new_api_params(self.API_DP_GET, "2.0")
        params.put_post_data("devId", dev_id)
        params.put_post_data("gwId", gw_id)
        return self.business.request(params)

    def get_dps_v1(self, gw_id: str, dev_id: str) -> BusinessResult:
        """``pppbppp(gwId, devId, cb)`` — ``s.m.dev.dp.get`` v1.0 → DpResp;
        postData ``{gwId, devId}``, session required."""

        params = self.business.new_api_params(self.API_DP_GET, "1.0")
        params.put_post_data("gwId", gw_id)
        params.put_post_data("devId", dev_id)
        return self.business.request(params)
