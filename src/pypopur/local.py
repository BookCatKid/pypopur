"""Local Tuya LAN transport using a user-owned per-device local key."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from importlib import import_module
from typing import Any, Protocol

from .codec import decode_raw_bytes
from .dps import normalize_dp_mapping
from .exceptions import (
    HandshakeError,
    MissingLocalKey,
    ProtocolError,
    TransportDependencyMissing,
    TransportError,
)
from .transport import PopurTransport


class _TinyTuyaDevice(Protocol):
    def set_version(self, version: float) -> Any: ...
    def status(self) -> Any: ...
    def set_multiple_values(self, data: Mapping[int | str, Any]) -> Any: ...
    def close(self) -> Any: ...


DeviceFactory = Callable[[str, str, str], _TinyTuyaDevice]


@dataclass(frozen=True, slots=True)
class LocalDeviceConfig:
    """Credentials and connection data for a device already owned by the user."""

    host: str
    device_id: str
    local_key: str
    protocol_version: str | None = None
    timeout: float = 5.0

    def __repr__(self) -> str:
        return (
            f"LocalDeviceConfig(host={self.host!r}, device_id={self.device_id!r}, "
            f"local_key=<redacted>, protocol_version={self.protocol_version!r}, "
            f"timeout={self.timeout!r})"
        )


def _default_device_factory(device_id: str, host: str, local_key: str) -> _TinyTuyaDevice:
    try:
        tinytuya = import_module("tinytuya")
    except ImportError as err:
        raise TransportDependencyMissing(
            "Local LAN control requires the 'tinytuya' dependency"
        ) from err
    return tinytuya.Device(device_id, host, local_key)


class LocalTuyaTransport(PopurTransport):
    """Async wrapper around TinyTuya's local protocol implementation.

    Popur app-v2 models use hexadecimal strings for the packed RAW datapoints, while the Thing
    SDK LAN path carries schema-RAW values Base64-encoded; ``write_dps`` performs that
    conversion so wire payloads match the official client.  This class never
    obtains a local key from Popur or Tuya cloud: callers must supply a legitimate
    key for their own device.

    The APK exposes Thing SDK support for local protocol 3.3, 3.4, 3.5 and 3.5.1 but does not
    prove which one an S7 uses. TinyTuya exposes 3.5/3.4/3.3 as ordinary versions, so with
    ``protocol_version=None`` this transport performs read-only status probes in that order.
    The SDK's distinct 3.5.1 branch is documented but is not guessed through TinyTuya's float
    version API. An explicit version skips probing.
    """

    AUTO_PROTOCOL_VERSIONS = ("3.5", "3.4", "3.3")

    # Firmware-4 schema-RAW datapoints that the official SDK Base64-encodes before
    # LAN delivery. DP125 is also a packed model family member but is an integer
    # bitmask on the wire, so it is deliberately excluded.
    RAW_WIRE_DP_IDS = frozenset({101, 102, 103, 104, 105, 106})

    def __init__(
        self,
        host: str,
        device_id: str,
        local_key: str,
        *,
        protocol_version: str | None = None,
        timeout: float = 5.0,
        _device_factory: DeviceFactory | None = None,
    ) -> None:
        if not host.strip():
            raise ValueError("host must not be empty")
        if not device_id.strip():
            raise ValueError("device_id must not be empty")
        if not local_key:
            raise MissingLocalKey("A per-device local key is required for LAN control")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._config = LocalDeviceConfig(host, device_id, local_key, protocol_version, timeout)
        self._device_factory = _device_factory or _default_device_factory
        self._device: _TinyTuyaDevice | None = None
        self._selected_protocol_version: str | None = None
        self._last_dps: dict[int, Any] = {}
        self._lock = asyncio.Lock()

    @property
    def config(self) -> LocalDeviceConfig:
        return self._config

    @property
    def protocol_version(self) -> str | None:
        """The explicit or successfully probed local protocol version."""

        return self._selected_protocol_version

    @property
    def connected(self) -> bool:
        return self._device is not None

    def _make_device(self, protocol_version: str) -> _TinyTuyaDevice:
        device = self._device_factory(
            self._config.device_id,
            self._config.host,
            self._config.local_key,
        )
        try:
            device.set_version(float(protocol_version))
            set_timeout = getattr(device, "set_socketTimeout", None)
            if callable(set_timeout):
                set_timeout(self._config.timeout)
            set_persistent = getattr(device, "set_socketPersistent", None)
            if callable(set_persistent):
                set_persistent(True)
        except Exception as err:
            self._safe_close_sync(device)
            raise ProtocolError(f"Unsupported local protocol version {protocol_version!r}") from err
        return device

    @staticmethod
    def _safe_close_sync(device: _TinyTuyaDevice | None) -> None:
        if device is None:
            return
        try:
            device.close()
        except (OSError, RuntimeError, ValueError, TypeError):
            pass

    @staticmethod
    def _response_error(response: Any) -> tuple[int | None, str] | None:
        if not isinstance(response, Mapping):
            return None
        error = response.get("Error")
        err_code = response.get("Err")
        if error is None and err_code is None:
            return None
        try:
            code = int(err_code) if err_code is not None else None
        except (TypeError, ValueError):
            code = None
        return code, str(error or "unknown TinyTuya error")

    @classmethod
    def _raise_response_error(cls, response: Any) -> None:
        parsed = cls._response_error(response)
        if parsed is None:
            return
        code, message = parsed
        # TinyTuya 914 is "key OR version" and cannot reliably distinguish an
        # invalid local key from a wrong protocol version.
        if code == 914:
            raise HandshakeError(
                "Device rejected the local handshake (local key or protocol version)"
            )
        suffix = f" (TinyTuya error {code})" if code is not None else ""
        raise TransportError(f"{message}{suffix}")

    @classmethod
    def _extract_dps(cls, response: Any) -> dict[int, Any]:
        cls._raise_response_error(response)
        if not isinstance(response, Mapping):
            raise ProtocolError("Local status response was not a mapping")
        payload = response.get("dps")
        if not isinstance(payload, Mapping):
            raise ProtocolError("Local status response did not contain a DPS mapping")
        return normalize_dp_mapping(payload)

    async def _probe(self, version: str) -> tuple[_TinyTuyaDevice, dict[int, Any]]:
        device = self._make_device(version)
        try:
            response = await asyncio.to_thread(device.status)
            dps = self._extract_dps(response)
        except (TransportError, ProtocolError):
            await asyncio.to_thread(self._safe_close_sync, device)
            raise
        except (OSError, RuntimeError, ValueError, TypeError) as err:
            await asyncio.to_thread(self._safe_close_sync, device)
            raise TransportError(
                f"Local status probe failed for protocol {version}: {err}"
            ) from err
        return device, dps

    async def connect(self) -> None:
        async with self._lock:
            if self._device is not None:
                return
            versions = (
                (self._config.protocol_version,)
                if self._config.protocol_version is not None
                else self.AUTO_PROTOCOL_VERSIONS
            )
            failures: list[tuple[str, Exception]] = []
            for version in versions:
                try:
                    device, dps = await self._probe(version)
                except TransportDependencyMissing:
                    raise
                except (
                    TransportError,
                    ProtocolError,
                    OSError,
                    RuntimeError,
                    ValueError,
                    TypeError,
                ) as err:
                    failures.append((version, err))
                    continue
                self._device = device
                self._selected_protocol_version = version
                self._last_dps = dps
                return
            if len(failures) == 1:
                raise failures[0][1]
            details = "; ".join(f"pv {version}: {error}" for version, error in failures)
            if failures and all(isinstance(error, HandshakeError) for _, error in failures):
                raise HandshakeError(
                    "Local handshake failed for all supported probe versions; the APK does not "
                    "provide enough evidence to distinguish a wrong local key from an unsupported "
                    f"protocol version ({details})"
                )
            raise TransportError(f"Unable to connect to local device ({details})")

    async def close(self) -> None:
        async with self._lock:
            device = self._device
            self._device = None
            self._selected_protocol_version = None
            if device is not None:
                await asyncio.to_thread(self._safe_close_sync, device)

    async def read_dps(self, ids: Collection[int] | None = None) -> Mapping[int, Any]:
        await self.connect()
        async with self._lock:
            device = self._device
            # ``connect`` and ``close`` use this same lock, so the device cannot disappear here
            # today. Keep the guard for future lifecycle changes without fabricating a test-only
            # race that the lock intentionally makes unreachable.
            if device is None:  # pragma: no cover - defensive invariant guard
                raise TransportError("Local transport is not connected")
            try:
                response = await asyncio.to_thread(device.status)
                dps = self._extract_dps(response)
            except (TransportError, ProtocolError):
                raise
            except Exception as err:
                raise TransportError(f"Local status read failed: {err}") from err
            # Protocol 3.5 status replies may contain only datapoints that the
            # device chose to report in that frame. Preserve values from the
            # successful connection probe and merge subsequent partial frames
            # into the point-in-time state exposed to callers.
            self._last_dps.update(dps)
            merged = dict(self._last_dps)
            if ids is None:
                return merged
            requested = set(ids)
            return {dp: value for dp, value in merged.items() if dp in requested}

    async def write_dps(self, values: Mapping[int, Any]) -> None:
        if not values:
            return
        wire_values = {str(int(dp)): value for dp, value in values.items()}
        # The official SDK encodes schema-RAW values as Base64 before LAN delivery
        # (DevUtil.encodeRaw). Keep the caller-facing representation unchanged and
        # reject undecodable packed payloads before any network I/O.
        for dp, value in values.items():
            if int(dp) not in self.RAW_WIRE_DP_IDS:
                continue
            raw = decode_raw_bytes(value, allow_base64=True)
            if raw is None:
                raise ProtocolError(f"Invalid raw byte payload for DP{int(dp)}")
            wire_values[str(int(dp))] = base64.b64encode(raw).decode("ascii")
        await self.connect()
        async with self._lock:
            device = self._device
            # See the matching read guard above: the shared lock makes this unreachable today.
            if device is None:  # pragma: no cover - defensive invariant guard
                raise TransportError("Local transport is not connected")
            try:
                response = await asyncio.to_thread(device.set_multiple_values, wire_values)
                self._raise_response_error(response)
            except TransportError:
                raise
            except Exception as err:
                raise TransportError(f"Local DPS write failed: {err}") from err
            self._last_dps.update({int(dp): value for dp, value in values.items()})
