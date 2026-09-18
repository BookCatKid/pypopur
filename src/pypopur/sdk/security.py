"""Port of the ATOP signing layer.

Java references (smali_classes3):
- ``com.thingclips.sdk.network.ThingApiSignManager`` — request signing:
  whitelist + sort + ``||`` join + postData MD5-swap, then the native
  ``doCommandNative(ctx, 1, canonical, null, mD)`` String result.
- ``com.thingclips.sdk.network.ThingNetworkSecurity`` — Java wrappers over
  ``JNICLibrary``/``SecureNativeApi``: ``getEncryptoKey``, ``genKey``,
  ``getChKey``, ``computeDigest``, ``encryptPostData``.
- ``MD5Util.md5AsBase64`` — misnamed: lowercase hex MD5.

The native functions are pure HMAC/MD5 primitives keyed by the cmd-0 runtime
globals (``RUNTIME_GLOBAL_S`` etc.); see ``docs/parity/02-security.md`` and
``popur-research/THING_SECURITY_AUDIT.md``. For Popur 2.0.0 the resolved
``GLOBAL_S`` ships in ``pypopur.popur_app2_material.APP2_NATIVE_MASTER_HEX``
and the ``getChKey`` output is the constant ``APP2_CH_KEY``.

``doCommandNative`` cmd 1 (the ``sign`` field) is verified by native
emulation as nested MD5 — ``md5hex(md5hex(GLOBAL_S) + canonical)`` —
via the ``hmacWrap`` helper @0x12eb4 (double ``digestHex`` with a
concat in between). See ``popur-research/emu_jni.py`` /
``emu_vectors.py`` for the vector harness.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Mapping, MutableMapping

from ._java import text_is_empty

# ThingApiSignManager.<clinit> — whitelist, array order (NOT sorted order).
SIGN_WHITELIST = (
    "a",
    "v",
    "lat",
    "lon",
    "lang",
    "deviceId",
    "appVersion",
    "ttid",
    "isH5",
    "h5Token",
    "os",
    "clientId",
    "postData",
    "time",
    "requestId",
    "et",
    "n4h5",
    "sid",
    "chKey",
    "sp",
)
_SIGN_WHITELIST_SET = frozenset(SIGN_WHITELIST)


def md5_as_base64(value: str) -> str:
    """``MD5Util.md5AsBase64`` — lowercase hex MD5 (the name lies)."""

    return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()


def md5_as_base64_for16(value: str) -> str:
    """``MD5Util.md5AsBase64For16`` — ``md5_as_base64(v)[8:24]``."""

    return md5_as_base64(value)[8:24]


def swap_sign_string(h: str) -> str:
    """``ThingApiSignManager.swapSignString``: for 32-char ``h``,
    ``h[8:16] + h[0:8] + h[24:32] + h[16:24]`` (Tuya MD5 reorder)."""

    return h[8:16] + h[0:8] + h[24:32] + h[16:24]


def post_data_md5_hex(value: str) -> str:
    """``ThingApiSignManager.postDataMD5Hex`` =
    ``swapSignString(md5hex_lower(value))``."""

    return swap_sign_string(md5_as_base64(value))


def default_signer(canonical: str, key_material: str | bytes) -> str:
    """``doCommandNative`` cmd 1 — nested MD5 over the canonical string:
    ``md5hex(md5hex(GLOBAL_S) + canonical)`` (32 lowercase hex). Verified by
    emulating the cmd-1 path to ``hmacWrap`` @0x12eb4:
    ``digestHex(concat(digestHex(GLOBAL_S), msg))``. Inject ``signer`` on
    :class:`ThingApiSignManager` to override."""

    key = key_material if isinstance(key_material, bytes) else key_material.encode()
    inner = hashlib.md5(key, usedforsecurity=False).hexdigest().encode()
    return hashlib.md5(inner + canonical.encode(), usedforsecurity=False).hexdigest()


class ThingApiSignManager:
    """Static-method port holding the injectable seams
    (``signer`` = cmd 1, ``key_material`` = GLOBAL_S)."""

    def __init__(
        self,
        key_material: str | bytes,
        signer: Callable[[str, str | bytes], str] | None = None,
    ) -> None:
        self._key_material = key_material
        self._signer = signer or default_signer

    def generate_signature_sdk(self, params: MutableMapping[str, str]) -> str:
        """``generateSignatureSdk(Map)`` (167-472).

        Sorts keys lexicographically, keeps whitelist entries with nonempty
        values, replaces a nonempty ``postData`` value IN PLACE with
        ``postDataMD5Hex``, joins ``k=v`` with ``||``, signs via cmd 1.
        """

        joined = []
        for key in sorted(params.keys()):
            if key not in _SIGN_WHITELIST_SET:
                continue
            value = params[key]
            if text_is_empty(value):
                continue
            if key == "postData":
                value = post_data_md5_hex(value)
                params[key] = value
            joined.append(f"{key}={value}")
        canonical = "||".join(joined)
        return self._signer(canonical, self._key_material)

    # generateSignature(map, apiParams) delegates straight to the SDK variant.
    generate_signature = generate_signature_sdk

    @staticmethod
    def get_request_key_by_sorted(params: Mapping[str, str]) -> str:
        """``getRequestKeyBySorted``: sort+join with NO whitelist and no
        postData swap, then ``md5AsBase64(joined)``. Dedup/request keys."""

        joined = "||".join(f"{k}={params[k]}" for k in sorted(params.keys()))
        return md5_as_base64(joined)


class ThingNetworkSecurity:
    """Port of the ``ThingNetworkSecurity`` Java wrappers.

    ``global_s`` is the cmd-0 ``RUNTIME_GLOBAL_S`` (the four-component
    underscore-joined string). ``global_d``/``global_c`` feed ``get_ch_key``
    only; Popur ships the constant output ``APP2_CH_KEY`` so they are
    optional.
    """

    def __init__(
        self,
        global_s: str | bytes,
        global_d: str = "",
        global_c: str = "",
    ) -> None:
        # GLOBAL_S embeds the binary transformed security component, so it is
        # stored as UTF bytes (the native build concats GetStringUTFChars).
        self._global_s = global_s if isinstance(global_s, bytes) else global_s.encode()
        self._global_d = global_d
        self._global_c = global_c

    def get_encrypto_key(self, request_id: str, ecode: str | None) -> bytes:
        """``getEncryptoKey(a, b)`` — HMAC-SHA256(key=a,
        data=GLOBAL_S+"_"+b) → hex[:16] as 16 ASCII bytes.

        NULL ``ecode`` (``cbz x21`` @0x14d18 → empty tmp → data falls
        back to ``GLOBAL_S``) differs from a non-null empty ecode
        (``GLOBAL_S + "_"``). Matches ``mobile.derive_request_key``.
        """

        msg = self._global_s if ecode is None else self._global_s + b"_" + ecode.encode()
        return hmac.new(request_id.encode(), msg, hashlib.sha256).hexdigest()[:16].encode("ascii")

    def gen_key(self, a: str, b: str, c: str) -> str:
        """``genKey(a, b, c)`` — HMAC-SHA256(key=a,
        data=c+"_"+GLOBAL_S+"_"+nibblePermute(b)) → hex[:16].

        The native permute loops ``min(strlen(b),16)`` times reading
        ``b[b[i]&0xF]`` — indexes past ``len(b)`` read the NUL-padded tail
        of the UTF buffer, mirrored here by ``ljust(16, "\\0")``."""

        buf = b.ljust(16, "\0")
        perm = "".join(buf[ord(ch) & 0xF] for ch in b[:16])
        msg = c.encode() + b"_" + self._global_s + b"_" + perm.encode()
        return hmac.new(a.encode(), msg, hashlib.sha256).hexdigest()[:16]

    def get_ch_key(self, data: bytes) -> str:
        """``getChKey(ctx, bytes)`` — HMAC-SHA256(key=bytes,
        data=GLOBAL_D+"_"+GLOBAL_C) → hex64[8:16]."""

        msg = f"{self._global_d}_{self._global_c}"
        return hmac.new(data, msg.encode(), hashlib.sha256).hexdigest()[8:16]

    def compute_digest(self, arg0: str, arg1: str) -> str:
        """``computeDigest(a, b)`` — MD5(b + "||" + a + "_" + GLOBAL_S)
        → 32 lowercase hex."""

        return hashlib.md5(
            arg1.encode() + b"||" + arg0.encode() + b"_" + self._global_s,
            usedforsecurity=False,
        ).hexdigest()

    def encrypt_post_data(self, key_str: str, ignored: bytes) -> bytes:
        """``encryptPostData(key, bytes)`` — the byte[] arg is IGNORED by
        this build; returns HMAC-SHA256(key=key_str, data=GLOBAL_S)[:16]
        as 16 ASCII-hex bytes (audit §A sibling)."""

        del ignored
        return (
            hmac.new(key_str.encode(), self._global_s, hashlib.sha256)
            .hexdigest()[:16]
            .encode("ascii")
        )
