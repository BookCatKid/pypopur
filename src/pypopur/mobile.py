"""Thing/Tuya mobile-account bootstrap used by the Popur app-v2 family.

The request flow mirrors the official Popur Android app. The audited Popur App-2 application
identity can be used through a version-bound bundled profile, reconstructed directly from the APK,
or supplied explicitly by callers working with another deployment.
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any, Final, Protocol

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .discovery import DiscoveredS7
from .dps import decode_snapshot, normalize_dp_mapping
from .exceptions import AuthenticationError, PopurError, ProtocolError, TransportError
from .local import LocalDeviceConfig
from .models import DeviceSnapshot
from .reference import S7_PRODUCT_IDS

POPUR_APP2_PACKAGE_NAME: Final = "com.smartapp.popur.app"
POPUR_APP2_APP_VERSION: Final = "2.0.0"
POPUR_APP2_SDK_VERSION: Final = "6.7.0"
POPUR_APP2_DEVICE_CORE_VERSION: Final = "6.7.0"
POPUR_APP2_TTID: Final = "android"
POPUR_APP2_SECURITY_ASSET: Final = "assets/t_s.bmp"
POPUR_APP2_BUILD_CONFIG: Final = "Lcom/smartapp/popur/app/BuildConfig;"
# Popur App 2 ships a custom domain config (assets/t_cdc.tcfg, AES-GCM with key=appId[:16],
# nonce=appSecret, AAD=packageName) that overrides the SDK's default Thing region table. These
# are the mobileApiUrl values from that config.
POPUR_APP2_REGION_HOSTS: Final[Mapping[str, str]] = {
    "us": "https://a1-us.iotbing.com",
    "eu": "https://a1.tuyaeu.com",
    "in": "https://a1-in.iotbing.com",
}

_SIGN_FIELDS: Final = frozenset(
    {
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
    }
)


class MobileApiError(PopurError):
    """The Thing mobile API returned an application-level error."""

    def __init__(self, code: str | None, message: str | None, *, action: str) -> None:
        self.code = code or "UNKNOWN"
        self.message = message or "Unknown mobile API error"
        self.action = action
        super().__init__(f"{action}: {self.code}: {self.message}")


class MobileAuthenticationError(AuthenticationError):
    """Popur account authentication was rejected."""


class AccountDeviceNotFound(PopurError):
    """The authenticated account does not expose the discovered S7."""


@dataclass(frozen=True, slots=True, repr=False)
class MobileAppProfile:
    """Thing mobile-app identity and native security material.

    ``client_id``, ``ch_key``, ``signing_key`` and ``encryption_secret`` are app-identity or
    credential-equivalent material and are always redacted from object representations.
    """

    api_host: str
    client_id: str
    app_version: str
    sdk_version: str
    ttid: str
    ch_key: str
    signing_key: bytes = field(repr=False)
    encryption_secret: bytes = field(repr=False)
    package_name: str | None = None
    device_core_version: str | None = None
    lang: str = "en_US"
    os_name: str = "Android"
    channel: str = "sdk"
    os_system: str | None = None
    platform: str | None = None
    time_zone_id: str | None = None
    neutral_domain: bool = False
    sdk_int: int | str | None = None
    brand: str | None = None
    biz_data: Mapping[str, Any] = field(default_factory=lambda: {"customDomainSupport": "1"})
    extra_params: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("api_host", "client_id", "app_version", "sdk_version", "ttid", "ch_key"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"{name} must not be empty")
        if not self.signing_key:
            raise ValueError("signing_key must not be empty")
        if not self.encryption_secret:
            raise ValueError("encryption_secret must not be empty")
        if not self.channel.strip():
            raise ValueError("channel must not be empty")

    @classmethod
    def from_native_components(
        cls,
        *,
        api_host: str,
        client_id: str,
        app_version: str,
        sdk_version: str,
        ttid: str,
        package_name: str,
        certificate_sha256: str,
        transformed_security_component: str | bytes,
        app_secret: str,
        ch_key: str | None = None,
        **kwargs: Any,
    ) -> MobileAppProfile:
        """Derive the native signing and encryption material from app-owned components.

        Popur App 2's bundled ``libthing_security.so`` constructs the native security byte string
        as ``packageName + '_' + certificateSHA256 + '_' + transformedComponent[0] + '_' +
        appSecret``. ``transformed_security_component`` is specifically the first component after
        the native parser/transform has processed the app-owned security asset; callers must not
        pass the raw asset/blob here. The transformed component is binary in the inspected App-2
        build, so callers may pass it as ``bytes``. The resulting master is the HMAC-SHA256 key used
        for request signing and is also the secret message material used by ``getEncryptoKey``. It
        is deliberately supplied at runtime rather than embedded here.
        """

        components = {
            "package_name": package_name,
            "certificate_sha256": certificate_sha256,
            "app_secret": app_secret,
        }
        for name, value in components.items():
            if not value.strip():
                raise ValueError(f"{name} must not be empty")
        if isinstance(transformed_security_component, str):
            if not transformed_security_component:
                raise ValueError("transformed_security_component must not be empty")
            security_component_bytes = transformed_security_component.encode()
        else:
            security_component_bytes = bytes(transformed_security_component)
            if not security_component_bytes:
                raise ValueError("transformed_security_component must not be empty")

        certificate_sha256 = normalize_certificate_sha256(certificate_sha256)
        ch_key = ch_key or derive_ch_key(client_id, package_name, certificate_sha256)
        master = (
            package_name.encode()
            + b"_"
            + certificate_sha256.encode()
            + b"_"
            + security_component_bytes
            + b"_"
            + app_secret.encode()
        )
        return cls(
            api_host=api_host,
            client_id=client_id,
            app_version=app_version,
            sdk_version=sdk_version,
            ttid=ttid,
            ch_key=ch_key,
            signing_key=master,
            encryption_secret=master,
            package_name=package_name,
            **kwargs,
        )

    def __repr__(self) -> str:
        return (
            "MobileAppProfile("
            f"api_host={self.api_host!r}, client_id=<redacted>, "
            f"app_version={self.app_version!r}, sdk_version={self.sdk_version!r}, "
            f"ttid={self.ttid!r}, ch_key=<redacted>, channel={self.channel!r}, "
            "signing_key=<redacted>, "
            "encryption_secret=<redacted>)"
        )

    @classmethod
    def for_popur_app2(
        cls,
        *,
        client_id: str,
        certificate_sha256: str,
        transformed_security_component: str | bytes,
        app_secret: str,
        region: str = "us",
        **kwargs: Any,
    ) -> MobileAppProfile:
        """Build the fixed, non-secret App-2 profile around runtime OEM security material.

        Region selection mirrors the Thing region hosts present in the SDK. This helper keeps
        credential-equivalent app identity/security inputs explicit while filling only public,
        version-bound Popur App-2 metadata.
        """

        normalized_region = region.strip().lower()
        try:
            api_host = POPUR_APP2_REGION_HOSTS[normalized_region]
        except KeyError as err:
            supported = ", ".join(sorted(POPUR_APP2_REGION_HOSTS))
            raise ValueError(
                f"unsupported App-2 region {region!r}; expected one of {supported}"
            ) from err
        return cls.from_native_components(
            api_host=api_host,
            client_id=client_id,
            app_version=POPUR_APP2_APP_VERSION,
            sdk_version=POPUR_APP2_SDK_VERSION,
            device_core_version=POPUR_APP2_DEVICE_CORE_VERSION,
            ttid=POPUR_APP2_TTID,
            package_name=POPUR_APP2_PACKAGE_NAME,
            certificate_sha256=certificate_sha256,
            transformed_security_component=transformed_security_component,
            app_secret=app_secret,
            neutral_domain=True,
            **kwargs,
        )

    @classmethod
    def bundled_popur_app2(cls, *, region: str = "us", **kwargs: Any) -> MobileAppProfile:
        """Use the version-bound identity extracted from the distributed Popur App-2 APK."""

        from .popur_app2_material import APP2_CH_KEY, APP2_CLIENT_ID, APP2_NATIVE_MASTER_HEX

        normalized_region = region.strip().lower()
        try:
            api_host = POPUR_APP2_REGION_HOSTS[normalized_region]
        except KeyError as err:
            supported = ", ".join(sorted(POPUR_APP2_REGION_HOSTS))
            raise ValueError(
                f"unsupported App-2 region {region!r}; expected one of {supported}"
            ) from err
        master = bytes.fromhex(APP2_NATIVE_MASTER_HEX)
        return cls(
            api_host=api_host,
            client_id=APP2_CLIENT_ID,
            app_version=POPUR_APP2_APP_VERSION,
            sdk_version=POPUR_APP2_SDK_VERSION,
            device_core_version=POPUR_APP2_DEVICE_CORE_VERSION,
            ttid=POPUR_APP2_TTID,
            ch_key=APP2_CH_KEY,
            signing_key=master,
            encryption_secret=master,
            package_name=POPUR_APP2_PACKAGE_NAME,
            neutral_domain=True,
            **kwargs,
        )

    @classmethod
    def from_popur_app2_apk(
        cls,
        apk_path: str | os.PathLike[str],
        *,
        region: str = "us",
        **kwargs: Any,
    ) -> MobileAppProfile:
        """Build a complete Popur App-2 profile directly from the official APK.

        The OEM app ID/secret are read from the APK's DEX ``BuildConfig`` constants; the Android
        signing-certificate fingerprint is read from the APK v2/v3 signing block; and the native
        security component is reconstructed from the bundled ``assets/t_s.bmp`` using the exact
        current-generation Thing parser. No OEM secret needs to be copied into pypopur source.
        """

        config = extract_popur_app2_build_config(apk_path)
        package_name = str(config["APPLICATION_ID"])
        if package_name != POPUR_APP2_PACKAGE_NAME:
            raise ValueError(
                f"APK package {package_name!r} is not the supported Popur App-2 package"
            )
        version = str(config["VERSION_NAME"])
        if version != POPUR_APP2_APP_VERSION:
            raise ValueError(
                f"APK version {version!r} is not the verified Popur App-2 version "
                f"{POPUR_APP2_APP_VERSION!r}"
            )
        client_id = str(config["THING_SMART_APPKEY"])
        app_secret = str(config["THING_SMART_SECRET"])
        if not client_id or not app_secret:
            raise ValueError("Popur APK contains empty Thing OEM application material")
        try:
            with zipfile.ZipFile(apk_path) as archive:
                bitmap = archive.read(POPUR_APP2_SECURITY_ASSET)
        except (OSError, KeyError, zipfile.BadZipFile) as err:
            raise ValueError(f"Popur APK does not contain {POPUR_APP2_SECURITY_ASSET}") from err
        components = extract_thing_security_components(client_id, bitmap)
        if not components:
            raise ValueError("Popur APK security asset yielded no components")
        return cls.for_popur_app2(
            client_id=client_id,
            certificate_sha256=extract_apk_signing_certificate_sha256(apk_path),
            transformed_security_component=components[0],
            app_secret=app_secret,
            region=region,
            **kwargs,
        )


@dataclass(frozen=True, slots=True, repr=False)
class MobileSession:
    """Authenticated mobile session returned by the Thing login endpoint."""

    sid: str
    ecode: str | None
    uid: str | None
    partner_identity: str | None
    domain: Mapping[str, Any]
    raw_user: Mapping[str, Any] = field(repr=False)

    def __repr__(self) -> str:
        return (
            "MobileSession(sid=<redacted>, ecode=<redacted>, "
            f"uid={self.uid!r}, partner_identity={self.partner_identity!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class AccountDevice:
    """Device identity returned by the authenticated account API."""

    device_id: str
    product_id: str | None
    name: str | None
    local_key: str | None = field(default=None, repr=False)
    ip: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __repr__(self) -> str:
        return (
            f"AccountDevice(device_id={self.device_id!r}, product_id={self.product_id!r}, "
            f"name={self.name!r}, local_key=<redacted>, ip={self.ip!r})"
        )


class FormPoster(Protocol):
    """Injectable async HTTP primitive used by the mobile API client."""

    async def __call__(
        self,
        url: str,
        data: Mapping[str, str],
        headers: Mapping[str, str],
        timeout: float,
    ) -> tuple[int, Mapping[str, str], bytes]: ...


def _swap_md5_blocks(value: str) -> str:
    if len(value) != 32:
        raise ValueError("expected a 32-character MD5 hex string")
    return value[8:16] + value[:8] + value[24:32] + value[16:24]


def _compact_json(value: Mapping[str, Any] | Sequence[Any]) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if offset >= len(data) or shift >= 35:
            raise ValueError("invalid DEX ULEB128 value")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7


def _dex_string(data: bytes, offset: int) -> str:
    # DEX strings use modified UTF-8. Popur's BuildConfig names/values are ASCII, so replacement
    # decoding is sufficient while still allowing us to walk unrelated non-ASCII strings safely.
    _, offset = _read_uleb128(data, offset)
    try:
        end = data.index(0, offset)
    except ValueError as err:
        raise ValueError("unterminated DEX string") from err
    return data[offset:end].decode("utf-8", errors="replace")


def _read_encoded_dex_value(data: bytes, offset: int) -> tuple[tuple[int, int | None], int]:
    if offset >= len(data):
        raise ValueError("truncated DEX encoded value")
    header = data[offset]
    offset += 1
    value_type = header & 0x1F
    value_arg = header >> 5
    if value_type == 0x1E:  # VALUE_NULL
        return (value_type, None), offset
    if value_type == 0x1F:  # VALUE_BOOLEAN
        return (value_type, value_arg), offset
    # Numeric, index and reference encodings all use value_arg + 1 little-endian bytes.
    if value_type in {
        0x00,
        0x02,
        0x03,
        0x04,
        0x06,
        0x10,
        0x11,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1A,
        0x1B,
    }:
        size = value_arg + 1
        end = offset + size
        if end > len(data):
            raise ValueError("truncated DEX encoded value payload")
        return (value_type, int.from_bytes(data[offset:end], "little")), end
    raise ValueError(f"unsupported DEX encoded value type 0x{value_type:02x}")


def _extract_build_config_from_dex(
    data: bytes, *, descriptor: str = POPUR_APP2_BUILD_CONFIG
) -> Mapping[str, Any] | None:
    """Extract static BuildConfig values from one DEX file without a decompiler."""

    if len(data) < 0x70 or not data.startswith(b"dex\n"):
        raise ValueError("invalid DEX file")
    string_count, string_offset = struct.unpack_from("<II", data, 0x38)
    type_count, type_offset = struct.unpack_from("<II", data, 0x40)
    field_count, field_offset = struct.unpack_from("<II", data, 0x50)
    class_count, class_offset = struct.unpack_from("<II", data, 0x60)

    def check_table(offset: int, count: int, width: int, name: str) -> None:
        if offset < 0 or count < 0 or offset + count * width > len(data):
            raise ValueError(f"invalid DEX {name} table")

    check_table(string_offset, string_count, 4, "string")
    check_table(type_offset, type_count, 4, "type")
    check_table(field_offset, field_count, 8, "field")
    check_table(class_offset, class_count, 32, "class")

    strings = [
        _dex_string(data, struct.unpack_from("<I", data, string_offset + index * 4)[0])
        for index in range(string_count)
    ]
    types = [
        strings[struct.unpack_from("<I", data, type_offset + index * 4)[0]]
        for index in range(type_count)
    ]
    fields: list[tuple[int, int, str]] = []
    for index in range(field_count):
        class_index, type_index, name_index = struct.unpack_from(
            "<HHI", data, field_offset + index * 8
        )
        fields.append((class_index, type_index, strings[name_index]))

    for index in range(class_count):
        (
            class_index,
            _access_flags,
            _superclass_index,
            _interfaces_offset,
            _source_file_index,
            _annotations_offset,
            class_data_offset,
            static_values_offset,
        ) = struct.unpack_from("<IIIIIIII", data, class_offset + index * 32)
        if types[class_index] != descriptor:
            continue
        if not class_data_offset or not static_values_offset:
            return {}

        cursor = class_data_offset
        static_count, cursor = _read_uleb128(data, cursor)
        instance_count, cursor = _read_uleb128(data, cursor)
        direct_count, cursor = _read_uleb128(data, cursor)
        virtual_count, cursor = _read_uleb128(data, cursor)
        del instance_count, direct_count, virtual_count

        static_field_indexes: list[int] = []
        field_index = 0
        for _ in range(static_count):
            field_delta, cursor = _read_uleb128(data, cursor)
            _field_flags, cursor = _read_uleb128(data, cursor)
            field_index += field_delta
            if field_index >= len(fields):
                raise ValueError("invalid DEX static field index")
            static_field_indexes.append(field_index)

        cursor = static_values_offset
        value_count, cursor = _read_uleb128(data, cursor)
        if value_count > len(static_field_indexes):
            raise ValueError("DEX BuildConfig has more values than static fields")
        result: dict[str, Any] = {}
        for value_index in range(value_count):
            (value_type, value), cursor = _read_encoded_dex_value(data, cursor)
            field_name = fields[static_field_indexes[value_index]][2]
            if value_type == 0x17:  # VALUE_STRING
                if value is None or value >= len(strings):
                    raise ValueError("invalid DEX string value index")
                result[field_name] = strings[value]
            elif value_type == 0x1F:
                result[field_name] = bool(value)
            else:
                result[field_name] = value
        return result
    return None


def extract_popur_app2_build_config(apk_path: str | os.PathLike[str]) -> Mapping[str, Any]:
    """Read Popur App-2 BuildConfig constants directly from an APK's DEX files."""

    try:
        with zipfile.ZipFile(apk_path) as archive:
            dex_names = sorted(
                name
                for name in archive.namelist()
                if name.startswith("classes") and name.endswith(".dex")
            )
            for name in dex_names:
                config = _extract_build_config_from_dex(archive.read(name))
                if config is not None:
                    required = {
                        "APPLICATION_ID",
                        "THING_SMART_APPKEY",
                        "THING_SMART_SECRET",
                        "VERSION_NAME",
                    }
                    if not required.issubset(config):
                        missing = ", ".join(sorted(required - set(config)))
                        raise ValueError(f"Popur BuildConfig is missing {missing}")
                    return config
    except (OSError, zipfile.BadZipFile) as err:
        raise ValueError("could not read Popur APK") from err
    raise ValueError("Popur App-2 BuildConfig was not found in APK")


def _read_length_prefixed(data: bytes, offset: int, *, width: int = 4) -> tuple[bytes, int]:
    if width not in (4, 8):
        raise ValueError("unsupported length-prefix width")
    if offset + width > len(data):
        raise ValueError("truncated length-prefixed value")
    fmt = "<I" if width == 4 else "<Q"
    size = struct.unpack_from(fmt, data, offset)[0]
    start = offset + width
    end = start + size
    if end > len(data):
        raise ValueError("truncated length-prefixed payload")
    return data[start:end], end


def extract_apk_signing_certificate_sha256(apk_path: str | os.PathLike[str]) -> str:
    """Extract the first APK v2/v3 signing certificate and return its SHA-256 fingerprint."""

    try:
        data = Path(apk_path).read_bytes()
    except OSError as err:
        raise ValueError("could not read Popur APK") from err
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 20 > len(data):
        raise ValueError("APK ZIP end record was not found")
    central_directory_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    magic = b"APK Sig Block 42"
    if (
        central_directory_offset < 24
        or data[central_directory_offset - 16 : central_directory_offset] != magic
    ):
        raise ValueError("APK v2/v3 signing block was not found")
    footer_size = struct.unpack_from("<Q", data, central_directory_offset - 24)[0]
    block_start = central_directory_offset - (footer_size + 8)
    if block_start < 0 or struct.unpack_from("<Q", data, block_start)[0] != footer_size:
        raise ValueError("invalid APK signing block")

    cursor = block_start + 8
    pairs_end = central_directory_offset - 24
    signing_ids = {0x7109871A, 0xF05368C0, 0x1B93AD61}
    while cursor < pairs_end:
        pair, cursor = _read_length_prefixed(data, cursor, width=8)
        if len(pair) < 4:
            raise ValueError("invalid APK signing-block pair")
        pair_id = struct.unpack_from("<I", pair, 0)[0]
        if pair_id not in signing_ids:
            continue
        value = pair[4:]
        signers, _ = _read_length_prefixed(value, 0)
        signer, _ = _read_length_prefixed(signers, 0)
        signed_data, _ = _read_length_prefixed(signer, 0)
        _digests, signed_cursor = _read_length_prefixed(signed_data, 0)
        certificates, _ = _read_length_prefixed(signed_data, signed_cursor)
        certificate, _ = _read_length_prefixed(certificates, 0)
        if not certificate:
            raise ValueError("APK signing certificate was empty")
        return hashlib.sha256(certificate).hexdigest()
    raise ValueError("APK v2/v3 signer certificate was not found")


def _java_string_hash(value: str) -> int:
    result = 0
    for byte in value.encode():
        result = ((result * 31) + byte) & 0xFFFFFFFF
    if result & 0x80000000:
        result -= 1 << 32
    return abs(result)


_THING_SECURITY_TRANSFORM_STREAM = bytes.fromhex(
    "ccc86e0bf722fe3eb9a89a80ffffffff9c9ac2c1aa6c1718f6d1d19ed2a134aa4aac2000ffffffff3cca8b0eaa0ca1c4636ec8a4f722fe3e26e80000ffffffff9c9ac2c1aa6c171859777731d2a134aad2000000ffffffff3cca8b0eaa0ca1c4ccc86e0bf722fe3e80000000ffffffff9c9ac2c1aa6c1718f6d1d19ed2a134aa00000000ffffffff3cca8b0eaa0ca1c4636ec8a4f722fe3e00000000ffffffff9c9ac2c1aa6c171859777731d2a134aa00000000ffffffff3cca8b0eaa0ca1c4ccc86e0bf722fe3e00000000ffffffff9c9ac2c1aa6c1718f6d1d19ed2a134aa00000000ffffffff3cca8b0eaa0ca1c4636ec8a4f722fe3e00000000ffffffff9c9ac2c1aa6c1718"
)


def _transform_thing_security_component(component: bytes) -> bytes:
    """Apply the deterministic final transform used by Thing's native bitmap parser."""

    if len(component) > len(_THING_SECURITY_TRANSFORM_STREAM):
        raise ValueError("Thing security component exceeds the native transform limit")
    return bytes(
        value ^ mask
        for value, mask in zip(
            component, _THING_SECURITY_TRANSFORM_STREAM[: len(component)], strict=True
        )
    )


def extract_thing_security_components(client_id: str, bitmap: bytes) -> tuple[bytes, ...]:
    """Decode the current Thing SDK's app-bound components from ``t_s.bmp``.

    This mirrors ``read_keys_from_content`` in Popur App 2's bundled
    ``libthing_security_algorithm.so``: a Java-style client-ID hash seeds an LSB bitstream cursor,
    encoded coefficient pairs are recovered, and each key is solved from its Vandermonde system.
    """

    if not client_id:
        raise ValueError("client_id must not be empty")
    if len(bitmap) < 54 or bitmap[:2] != b"BM":
        raise ValueError("Thing security asset is not a BMP file")
    pixel_offset = int.from_bytes(bitmap[10:14], "little")
    declared_size = int.from_bytes(bitmap[2:6], "little")
    if pixel_offset >= len(bitmap) or declared_size > len(bitmap):
        raise ValueError("Thing security BMP header is invalid")
    payload = bitmap[pixel_offset:declared_size]
    if not payload:
        raise ValueError("Thing security BMP has no pixel payload")

    cursor = ((_java_string_hash(client_id) % len(payload)) // 2) % len(payload) + 1

    def read_byte() -> int:
        nonlocal cursor
        value = 0
        for bit in range(8):
            value |= (payload[cursor % len(payload)] & 1) << bit
            cursor += 1
        return value

    key_count = read_byte()
    coefficient_count = read_byte()
    if not 1 <= key_count <= 5:
        raise ValueError("Thing security asset does not match client_id")
    if coefficient_count == 0 or coefficient_count % key_count:
        raise ValueError("Thing security asset has invalid coefficient count")
    cursor += 32

    pairs: list[tuple[int, int]] = []
    for _ in range(coefficient_count):
        first_size = read_byte()
        first = bytes(read_byte() for _ in range(first_size))
        second_size = read_byte()
        second = bytes(read_byte() for _ in range(second_size))
        if not first or not second:
            raise ValueError("Thing security asset contains an empty coefficient")
        pairs.append((int.from_bytes(first, "big"), int.from_bytes(second, "big")))

    per_key = coefficient_count // key_count
    results: list[bytes] = []
    for key_index in range(key_count):
        rows: list[list[Fraction]] = []
        for x_value, y_value in pairs[key_index * per_key : (key_index + 1) * per_key]:
            rows.append(
                [Fraction(pow(x_value, power)) for power in range(per_key - 1, -1, -1)]
                + [Fraction(y_value)]
            )
        for column in range(per_key):
            if rows[column][column] == 0:
                pivot = next(
                    (row for row in range(column + 1, per_key) if rows[row][column] != 0),
                    None,
                )
                if pivot is None:
                    raise ValueError("Thing security coefficient matrix is singular")
                rows[column], rows[pivot] = rows[pivot], rows[column]
            for row in range(column + 1, per_key):
                if rows[row][column] == 0:
                    continue
                ratio = rows[column][column] / rows[row][column]
                for cell in range(column, per_key + 1):
                    rows[row][cell] = rows[row][cell] * ratio - rows[column][cell]
        denominator = rows[-1][-2]
        if denominator == 0:
            raise ValueError("Thing security coefficient matrix is singular")
        solved = rows[-1][-1] / denominator
        if solved.denominator != 1 or solved.numerator < 0:
            raise ValueError("Thing security component is not an integer")
        encoded = format(solved.numerator, "x")
        if len(encoded) % 2:
            encoded = "0" + encoded
        try:
            component = bytes.fromhex(encoded)
        except ValueError as err:  # pragma: no cover - format() only returns hexadecimal
            raise ValueError("Thing security component was not hexadecimal") from err
        if not component:
            raise ValueError("Thing security component was empty")
        results.append(_transform_thing_security_component(component))
    return tuple(results)


def normalize_certificate_sha256(value: str) -> str:
    """Normalize an Android signing-certificate SHA-256 fingerprint.

    Thing's native security code formats the X.509 certificate digest as uppercase hexadecimal
    byte pairs separated by colons before it is used in the app-bound key derivations.
    """

    compact = value.strip().replace(":", "").upper()
    if len(compact) != 64 or any(char not in "0123456789ABCDEF" for char in compact):
        raise ValueError("certificate_sha256 must contain exactly 32 SHA-256 bytes")
    return ":".join(compact[index : index + 2] for index in range(0, 64, 2))


def derive_ch_key(app_id: str, package_name: str, certificate_sha256: str) -> str:
    """Derive the Thing ``chKey`` value bound to the app package and signing certificate."""

    if not app_id.strip():
        raise ValueError("app_id must not be empty")
    if not package_name.strip():
        raise ValueError("package_name must not be empty")
    certificate_sha256 = normalize_certificate_sha256(certificate_sha256)
    digest = hmac.new(
        app_id.encode(),
        package_name.encode() + b"_" + certificate_sha256.encode(),
        hashlib.sha256,
    ).hexdigest()
    return digest[8:16]


def derive_android_device_id(
    *,
    brand: str,
    model: str,
    random_id1: str,
    random_id2: str,
    random_id3: str,
    random_id4: str,
) -> str:
    """Reproduce ``PhoneUtil.getRemoteDeviceID`` from its persisted Android inputs."""

    values = {
        "brand": brand,
        "model": model,
        "random_id1": random_id1,
        "random_id2": random_id2,
        "random_id3": random_id3,
        "random_id4": random_id4,
    }
    for name, value in values.items():
        if not value:
            raise ValueError(f"{name} must not be empty")

    def md5_hex(text: str) -> str:
        return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()

    return (
        md5_hex(brand + model)[4:16]
        + md5_hex(random_id3 + random_id4)[8:24]
        + md5_hex(random_id1 + random_id2)[16:]
    )


def canonical_sign_input(params: Mapping[str, str]) -> str:
    """Build the SDK's sorted ``key=value||...`` signing string."""

    fields: dict[str, str] = {}
    for key, value in params.items():
        if key not in _SIGN_FIELDS or value == "":
            continue
        if key == "postData":
            digest = hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()
            value = _swap_md5_blocks(digest)
        fields[key] = value
    return "||".join(f"{key}={fields[key]}" for key in sorted(fields))


def sign_mobile_params(params: Mapping[str, str], signing_key: bytes) -> str:
    """Sign a Thing mobile request using the App-2 native HMAC-SHA256 primitive."""

    return hmac.new(signing_key, canonical_sign_input(params).encode(), hashlib.sha256).hexdigest()


def mobile_response_signature(result: str, timestamp: int | str, request_key: bytes) -> str:
    """Reproduce the SDK's encrypted-response integrity signature."""

    try:
        key_text = request_key.decode("ascii")
    except UnicodeDecodeError as err:
        raise ValueError("request_key must contain ASCII bytes") from err
    material = f"result={result}||t={timestamp}||{key_text}".encode()
    return hashlib.md5(material, usedforsecurity=False).hexdigest()


def derive_request_key(
    request_id: str,
    encryption_secret: bytes,
    ecode: str | None,
) -> bytes:
    """Derive the per-request AES-128 key used by ``et=3`` requests.

    ``getEncryptoKey`` HMACs the native master (optionally suffixed with ``_ecode``) with the
    request ID as the HMAC key, lower-hex encodes the digest, and returns its first 16 ASCII bytes.
    """

    # The native implementation branches on a null Java string, not on string emptiness.  A
    # non-null empty ecode therefore contributes the literal underscore separator.
    suffix = b"" if ecode is None else b"_" + ecode.encode()
    digest = hmac.new(request_id.encode(), encryption_secret + suffix, hashlib.sha256).digest()
    return digest.hex()[:16].encode("ascii")


def encrypt_mobile_payload(payload: str, key: bytes, *, nonce: bytes | None = None) -> str:
    """Encrypt an ATOP ``postData`` value for ``et=3`` requests.

    ``ThingApiParams.getEncryptPostDataString`` calls
    ``AesGcmUtil.encryptBytes2BytesAppendNonce``: AES-128-GCM with a fresh random nonce, no
    AAD, keyed by ``getEncryptoKey``. The output is ``nonce ++ ciphertext`` Base64-encoded.
    """

    if nonce is None:
        nonce = secrets.token_bytes(12)
    if len(nonce) != 12:
        raise ValueError("AES-GCM request nonce must be 12 bytes")
    if len(key) not in (16, 24, 32):
        raise ValueError("AES request key must be 16, 24 or 32 bytes")
    ciphertext = AESGCM(key).encrypt(nonce, payload.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_mobile_payload(payload: str, key: bytes, *, compressed: bool = False) -> bytes:
    """Decrypt an encrypted mobile API result and optionally gunzip it."""

    try:
        raw = base64.b64decode(payload, validate=True)
    except (ValueError, TypeError) as err:
        raise ProtocolError("Thing mobile API returned invalid base64 ciphertext") from err
    if len(raw) < 28:
        raise ProtocolError("Thing mobile API ciphertext is too short")
    try:
        plaintext = AESGCM(key).decrypt(raw[:12], raw[12:], None)
    except Exception as err:
        raise ProtocolError("Thing mobile API response decryption failed") from err
    if compressed or plaintext.startswith(b"\x1f\x8b"):
        try:
            plaintext = gzip.decompress(plaintext)
        except OSError as err:
            raise ProtocolError("Thing mobile API gzip response could not be decoded") from err
    return plaintext


def _stdlib_post_form_sync(
    url: str,
    data: Mapping[str, str],
    headers: Mapping[str, str],
    timeout: float,
) -> tuple[int, Mapping[str, str], bytes]:
    # Thing's regular Business transport uses Java URLEncoder and then replaces ``+`` (spaces)
    # with ``%20``.  Java leaves ``*`` unescaped but escapes ``~``, unlike Python's RFC-3986
    # defaults, so mirror that encoding exactly rather than relying on ``urlencode`` defaults.
    def _encode_component(value: str) -> str:
        return urllib.parse.quote(value, safe="-_.*").replace("~", "%7E")

    body = "&".join(
        f"{_encode_component(str(key))}={_encode_component(str(value))}"
        for key, value in data.items()
    ).encode()
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", **dict(headers)},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers.items()), err.read()
    except OSError as err:
        raise TransportError(f"Thing mobile API request failed: {err}") from err


async def _stdlib_post_form(
    url: str,
    data: Mapping[str, str],
    headers: Mapping[str, str],
    timeout: float,
) -> tuple[int, Mapping[str, str], bytes]:
    return await asyncio.to_thread(_stdlib_post_form_sync, url, data, headers, timeout)


class ThingMobileApi:
    """Minimal async client for the Thing mobile ATOP protocol used by Popur App 2."""

    def __init__(
        self,
        profile: MobileAppProfile,
        *,
        install_id: str | None = None,
        timeout: float = 10.0,
        _post_form: FormPoster | None = None,
        _clock: Callable[[], float] = time.time,
        _uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.profile = profile
        self._api_host = profile.api_host
        # Thing's persisted Android device ID is a 44-character lowercase hexadecimal value.  A
        # Python bootstrap has no Android Build identifiers/preferences to reproduce, so create the
        # same wire shape when the caller has not supplied a persisted identity explicitly.
        self.install_id = install_id or secrets.token_hex(22)
        self.timeout = timeout
        self.session: MobileSession | None = None
        self._post_form = _post_form or _stdlib_post_form
        self._clock = _clock
        self._uuid_factory = _uuid_factory

    @property
    def endpoint(self) -> str:
        host = self._api_host.rstrip("/")
        if host.endswith("/api.json"):
            return host
        if host.startswith(("http://", "https://")):
            return f"{host}/api.json"
        return f"https://{host}/api.json"

    @property
    def api_host(self) -> str:
        """Current ATOP host, including any post-login regional handoff."""

        return self._api_host

    def set_api_host(self, api_host: str) -> None:
        """Adopt a Thing API host returned by the authenticated account domain."""

        if not api_host.strip():
            raise ValueError("api_host must not be empty")
        self._api_host = api_host.strip()

    def _base_params(
        self,
        *,
        action: str,
        version: str,
        request_id: str,
        encrypted: bool,
        sid: str | None,
        gid: int | str | None,
    ) -> dict[str, str]:
        params = {
            "a": action,
            "v": version,
            "lang": self.profile.lang,
            "os": self.profile.os_name,
            "appVersion": self.profile.app_version,
            "sdkVersion": self.profile.sdk_version,
            "clientId": self.profile.client_id,
            "deviceId": self.install_id,
            "ttid": self.profile.ttid,
            "chKey": self.profile.ch_key,
            "channel": self.profile.channel,
            "et": "3" if encrypted else "0.0.1",
            "time": str(int(self._clock())),
            "requestId": request_id,
        }
        if self.profile.device_core_version:
            params["deviceCoreVersion"] = self.profile.device_core_version
        if self.profile.os_system:
            params["osSystem"] = self.profile.os_system
        if self.profile.platform:
            params["platform"] = self.profile.platform
        if self.profile.time_zone_id:
            params["timeZoneId"] = self.profile.time_zone_id
        biz_data = dict(self.profile.biz_data)
        if self.profile.neutral_domain:
            params["nd"] = "1"
            biz_data["nd"] = "1"
        if self.profile.sdk_int is not None:
            biz_data["sdkInt"] = str(self.profile.sdk_int)
        if self.profile.brand:
            biz_data["brand"] = self.profile.brand
        if biz_data:
            params["bizData"] = _compact_json(biz_data)
        if encrypted:
            params["cp"] = "gzip"
        params.update({str(key): str(value) for key, value in self.profile.extra_params.items()})
        if sid:
            params["sid"] = sid
        if gid is not None:
            params["gid"] = str(gid)
        return params

    async def request(
        self,
        action: str,
        version: str,
        post_data: Mapping[str, Any] | None = None,
        *,
        session_required: bool = True,
        encrypted: bool | None = None,
        gid: int | str | None = None,
    ) -> Any:
        """Execute one mobile ATOP request and return its decoded result."""

        session = self.session if session_required else None
        if session_required and session is None:
            raise MobileAuthenticationError("Thing mobile API request requires a login session")
        encrypted = session_required if encrypted is None else encrypted
        request_id = str(self._uuid_factory())
        # ThingApiParams.checkAPIName() rewrites "thing.*" API names to the legacy "smartlife.*"
        # namespace before they reach the wire; the server only accepts the rewritten form.
        wire_action = "smartlife" + action[len("thing") :] if action.startswith("thing") else action
        params = self._base_params(
            action=wire_action,
            version=version,
            request_id=request_id,
            encrypted=encrypted,
            sid=session.sid if session else None,
            gid=gid,
        )
        # ThingApiParams.hasPostData() checks whether the JSONObject exists, not whether it has
        # entries. Preserve the Java distinction between no postData (None) and an explicit empty
        # object ({}), because the latter is still encrypted and included in the request/signature.
        has_post_data = post_data is not None
        request_key: bytes | None = None
        if encrypted:
            request_key = derive_request_key(
                request_id,
                self.profile.encryption_secret,
                session.ecode if session else None,
            )
        if has_post_data:
            # ThingApiParams defaults signWhitEncryptedBody to true, so under et=3 the wire
            # postData is the AES-128-GCM encrypted string and the signature covers it.
            plain_post = _compact_json(post_data)
            if encrypted:
                if request_key is None:  # pragma: no cover
                    raise AssertionError("encrypted postData without request key")
                params["postData"] = encrypt_mobile_payload(plain_post, request_key)
            else:
                params["postData"] = plain_post
        params["sign"] = sign_mobile_params(params, self.profile.signing_key)

        request_headers = {
            "User-Agent": (
                f"Thing-UA=APP/Android/{self.profile.app_version}/SDK/{self.profile.sdk_version}"
            ),
            "Connection": "keep-alive",
            "x-client-trace-id": request_id,
        }
        status, headers, raw = await self._post_form(
            self.endpoint, params, request_headers, self.timeout
        )
        if not 200 <= status < 300:
            raise TransportError(f"Thing mobile API returned HTTP {status} for {action}")
        try:
            envelope = json.loads(raw.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            raise ProtocolError("Thing mobile API returned invalid JSON") from err
        if not isinstance(envelope, Mapping):
            raise ProtocolError("Thing mobile API response envelope was not an object")
        if envelope.get("success") is False:
            raise MobileApiError(
                _optional_text(envelope.get("errorCode")),
                _optional_text(envelope.get("errorMsg")),
                action=action,
            )
        result: Any = envelope.get("result")
        if encrypted:
            if not isinstance(result, str):
                raise ProtocolError("Thing mobile API encrypted response result was not a string")
            if request_key is None:  # pragma: no cover
                raise AssertionError("encrypted response without request key")
            response_sign = _optional_text(envelope.get("sign"))
            response_time = envelope.get("t")
            if response_sign is None or response_time is None:
                raise ProtocolError("Thing mobile API encrypted response was not signed")
            expected_sign = mobile_response_signature(result, response_time, request_key)
            if not hmac.compare_digest(response_sign.lower(), expected_sign):
                raise ProtocolError("Thing mobile API encrypted response signature was invalid")
            compressed = (_header_value(headers, "x-content-compress") or "").lower() == "gzip"
            plaintext = decrypt_mobile_payload(result, request_key, compressed=compressed)
            try:
                result = json.loads(plaintext.decode())
            except (UnicodeDecodeError, json.JSONDecodeError) as err:
                raise ProtocolError("Thing mobile API decrypted result was invalid JSON") from err
            # Current Thing mobile responses encrypt a second, complete response envelope rather
            # than encrypting only its ``result`` member. Older/synthetic deployments may still
            # return the result directly, so unwrap only when the envelope markers are present.
            if isinstance(result, Mapping) and "success" in result:
                if result.get("success") is False:
                    raise MobileApiError(
                        _optional_text(result.get("errorCode")),
                        _optional_text(result.get("errorMsg")),
                        action=action,
                    )
                result = result.get("result")
        return result


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _header_value(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return str(value)
    return None


def _require_mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtocolError(f"{context} response was not an object")
    return value


def _require_text(mapping: Mapping[str, Any], key: str, context: str) -> str:
    value = _optional_text(mapping.get(key))
    if value is None:
        raise ProtocolError(f"{context} response did not contain {key}")
    return value


def _rsa_encrypt_password(password: str, token: Mapping[str, Any]) -> str:
    modulus = _require_text(token, "publicKey", "login token")
    exponent = _require_text(token, "exponent", "login token")
    try:
        public_key = rsa.RSAPublicNumbers(int(exponent), int(modulus)).public_key()
    except (ValueError, TypeError) as err:
        raise ProtocolError("login token contained an invalid RSA public key") from err
    password_md5 = hashlib.md5(password.encode(), usedforsecurity=False).hexdigest().encode()
    return public_key.encrypt(password_md5, padding.PKCS1v15()).hex()


class PopurAccount:
    """Account bootstrap client matching Popur App 2's Thing SDK flow."""

    def __init__(self, api: ThingMobileApi) -> None:
        self.api = api

    @property
    def session(self) -> MobileSession | None:
        return self.api.session

    async def _login_token(self, email: str, country_code: str) -> Mapping[str, Any]:
        # Popur App 2 hardcodes country selector ``1`` for its email-login path.  Thing resolves
        # that selector to the US/AZ service host before the token request, independently of the
        # SDK's previously selected/default region.  Keep this Popur-specific routing behavior out
        # of generic profiles by applying it only to the official App-2 package identity.
        if country_code == "1" and self.api.profile.package_name == POPUR_APP2_PACKAGE_NAME:
            self.api.set_api_host(POPUR_APP2_REGION_HOSTS["us"])
        result = await self.api.request(
            "thing.m.user.username.token.get",
            "2.0",
            {"countryCode": country_code, "username": email, "isUid": False},
            session_required=False,
            encrypted=True,
        )
        return _require_mapping(result, "login token")

    async def login(
        self,
        email: str,
        password: str,
        *,
        country_code: str = "1",
    ) -> MobileSession:
        """Authenticate using the same two-stage email/password flow as Popur App 2."""

        if not email.strip():
            raise ValueError("email must not be empty")
        if not password:
            raise ValueError("password must not be empty")
        token = await self._login_token(email, country_code)
        encrypted_password = _rsa_encrypt_password(password, token)
        try:
            result = await self.api.request(
                "thing.m.user.email.password.login",
                "3.0",
                {
                    "countryCode": country_code,
                    "email": email,
                    "passwd": encrypted_password,
                    # Popur's Thing SDK inserts this value as a literal Java string rather than
                    # serializing an object. Keep the exact spacing from the APK so the decrypted
                    # login payload is byte-for-byte faithful to App 2.0.0.
                    "options": '{"group": 1}',
                    "token": _require_text(token, "token", "login token"),
                    # The SDK reports 1 when the RSA password encryption above succeeded.
                    "ifencrypt": 1,
                },
                session_required=False,
                encrypted=True,
            )
        except MobileApiError as err:
            code = err.code.upper()
            if any(piece in code for piece in ("PASSWORD", "PASSWD", "USER_", "LOGIN")):
                raise MobileAuthenticationError(str(err)) from err
            raise
        user = _require_mapping(result, "login")
        raw_ecode = user.get("ecode")
        session = MobileSession(
            sid=_require_text(user, "sid", "login"),
            # ``getEncryptoKey`` distinguishes a null Java string from an empty one.  Preserve
            # that distinction instead of normalizing an empty ecode to ``None``.
            ecode=None if raw_ecode is None else str(raw_ecode),
            uid=_optional_text(user.get("uid")),
            partner_identity=_optional_text(user.get("partnerIdentity")),
            domain=user.get("domain") if isinstance(user.get("domain"), Mapping) else {},
            raw_user=dict(user),
        )
        self.api.session = session
        mobile_api_url = _optional_text(session.domain.get("mobileApiUrl"))
        if mobile_api_url:
            self.api.set_api_host(mobile_api_url)
        return session

    async def homes(self) -> tuple[Mapping[str, Any], ...]:
        # The SDK constructs this ApiParams without a postData JSONObject at all.
        result = await self.api.request("m.life.home.space.list", "1.0")
        if result is None:
            return ()
        if not isinstance(result, list) or not all(isinstance(item, Mapping) for item in result):
            raise ProtocolError("home list response was not an array of objects")
        return tuple(dict(item) for item in result)

    async def home_detail(self, home_id: int | str) -> Mapping[str, Any]:
        result = await self.api.request("m.life.location.get", "3.4", {"gid": home_id})
        return _require_mapping(result, "home detail")

    async def home_devices(self, home_id: int | str) -> tuple[AccountDevice, ...]:
        result = await self.api.request("m.life.my.group.device.list", "2.2", {"gid": home_id})
        return _parse_device_list(result, "home device list")

    async def device_detail(
        self, device_id: str, *, home_id: int | str | None = None
    ) -> AccountDevice:
        result = await self.api.request(
            "thing.m.device.get", "4.1", {"devId": device_id}, gid=home_id
        )
        return _parse_device(_require_mapping(result, "device detail"))

    async def device_dps(
        self, device_id: str, *, home_id: int | str | None = None
    ) -> Mapping[int, Any]:
        """Return every current datapoint cached in the mobile device record.

        This is the same read-only ``thing.m.device.get`` record used by Popur App 2. It is
        useful for settings DPs that firmware does not include in an ordinary LAN status reply.
        """

        detail = await self.device_detail(device_id, home_id=home_id)
        point_info = detail.raw.get("dataPointInfo")
        if point_info is None:
            return {}
        info = _require_mapping(point_info, "device datapoint info")
        values = info.get("dps")
        if values is None:
            return {}
        return normalize_dp_mapping(_require_mapping(values, "device datapoints"))

    async def device_snapshot(
        self, device_id: str, *, home_id: int | str | None = None
    ) -> DeviceSnapshot:
        """Decode the complete read-only mobile device record into a snapshot."""

        return decode_snapshot(await self.device_dps(device_id, home_id=home_id))

    async def local_keys(
        self, gateway_id: str, *, node_ids: Sequence[str] | None = None
    ) -> tuple[tuple[str, str], ...]:
        post_data: dict[str, Any] = {"gwId": gateway_id}
        if node_ids:
            post_data["nodeIds"] = _compact_json(list(node_ids))
        result = await self.api.request("thing.m.device.key.get", "1.0", post_data)
        if result is None:
            return ()
        if not isinstance(result, list):
            raise ProtocolError("local-key response was not an array")
        keys: list[tuple[str, str]] = []
        for item in result:
            mapping = _require_mapping(item, "local-key item")
            keys.append(
                (
                    _require_text(mapping, "devId", "local-key item"),
                    _require_text(mapping, "localKey", "local-key item"),
                )
            )
        return tuple(keys)

    async def bootstrap_local_config(self, discovered: DiscoveredS7) -> LocalDeviceConfig:
        """Resolve the account credential for one passively discovered S7."""

        detail = await self.device_detail(discovered.device_id)
        if detail.product_id not in S7_PRODUCT_IDS:
            raise AccountDeviceNotFound(
                "The authenticated account device does not match the Popur S7 product family"
            )
        local_key = detail.local_key
        if not local_key:
            for device_id, candidate in await self.local_keys(discovered.device_id):
                if device_id == discovered.device_id:
                    local_key = candidate
                    break
        if not local_key:
            raise AccountDeviceNotFound(
                "The authenticated account did not return a local key for the discovered S7"
            )
        return LocalDeviceConfig(
            host=discovered.host,
            device_id=discovered.device_id,
            local_key=local_key,
            protocol_version=discovered.protocol_version,
        )


def _parse_device(mapping: Mapping[str, Any]) -> AccountDevice:
    return AccountDevice(
        device_id=_require_text(mapping, "devId", "device"),
        product_id=_optional_text(mapping.get("productId")),
        name=_optional_text(mapping.get("name")),
        local_key=_optional_text(mapping.get("localKey")),
        ip=_optional_text(mapping.get("ip")),
        raw=dict(mapping),
    )


def _parse_device_list(value: Any, context: str) -> tuple[AccountDevice, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ProtocolError(f"{context} response was not an array")
    return tuple(_parse_device(_require_mapping(item, context)) for item in value)


async def bootstrap_discovered_s7(
    discovered: DiscoveredS7,
    *,
    email: str,
    password: str,
    profile: MobileAppProfile,
    country_code: str = "1",
    install_id: str | None = None,
    timeout: float = 10.0,
    _post_form: FormPoster | None = None,
) -> LocalDeviceConfig:
    """One-shot account bootstrap from username/password to LAN credentials."""

    api = ThingMobileApi(
        profile,
        install_id=install_id,
        timeout=timeout,
        _post_form=_post_form,
    )
    account = PopurAccount(api)
    await account.login(email, password, country_code=country_code)
    return await account.bootstrap_local_config(discovered)


async def bootstrap_discovered_s7_from_apk(
    discovered: DiscoveredS7,
    *,
    email: str,
    password: str,
    apk_path: str | os.PathLike[str],
    country_code: str = "1",
    install_id: str | None = None,
    timeout: float = 10.0,
    _post_form: FormPoster | None = None,
) -> LocalDeviceConfig:
    """Bootstrap one discovered S7 using all App-2 identity material from the official APK."""

    profile = MobileAppProfile.from_popur_app2_apk(apk_path)
    return await bootstrap_discovered_s7(
        discovered,
        email=email,
        password=password,
        profile=profile,
        country_code=country_code,
        install_id=install_id,
        timeout=timeout,
        _post_form=_post_form,
    )


async def bootstrap_discovered_s7_popur_app2(
    discovered: DiscoveredS7,
    *,
    email: str,
    password: str,
    country_code: str = "1",
    install_id: str | None = None,
    timeout: float = 10.0,
    _post_form: FormPoster | None = None,
) -> LocalDeviceConfig:
    """Bootstrap a discovered S7 using Popur App 2's bundled, version-bound app identity.

    This is the normal Popur-specific entry point for integrations. It keeps the OEM application
    material out of configuration and returns only the LAN credentials needed for subsequent local
    operation. Account passwords and mobile-session values are not retained in the returned config.
    """

    return await bootstrap_discovered_s7(
        discovered,
        email=email,
        password=password,
        profile=MobileAppProfile.bundled_popur_app2(),
        country_code=country_code,
        install_id=install_id,
        timeout=timeout,
        _post_form=_post_form,
    )
