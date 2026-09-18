"""Port of ``com.thingclips.smart.android.common.utils.PhoneUtil`` device-ID
functions used to build the MQTT bean username/clientId.

smali: smali_classes3/com/thingclips/smart/android/common/utils/PhoneUtil.smali

- ``getDeviceID(ctx)``: static ``mDeviceId`` cache → persisted ``"deviceId"``
  (``SecuredPreferenceStore``) → :func:`remote_device_id` generated and
  persisted.
- ``getRemoteDeviceID``:
  ``md5(BRAND+MODEL)[4:16] + md5(randomId3+randomId4)[8:24] +
  md5(randomId1+randomId2)[16:]`` — 44 chars.
- ``generateRandomId``:
  ``last5(str(currentTimeMillis)) + first6(MODEL-without-spaces, '0'-padded)
  + first4(Long.toHexString(secureRandom.nextLong()))``.
- Each ``getRandomIdN`` caches in memory and persists under its own
  preference key.

The Android ``SharedPreferences``/``Build`` inputs are injected: ``store`` is
a ``MutableMapping[str, str]`` standing in for the preference file, and
``brand``/``model``/``clock``/``random`` stand in for ``Build.*``,
``System.currentTimeMillis()`` and ``SecureRandom``.
"""

from __future__ import annotations

import secrets as _secrets
import time
from collections.abc import Callable, MutableMapping

from .crypto import md5_upper


def _md5_lower(value: str) -> str:
    """``MD5Util.md5AsBase64`` — lowercase hex MD5 (misnamed in Java)."""

    return md5_upper(value).lower()


def generate_random_id(
    model: str, clock: Callable[[], int] | None = None, rng: Callable[[], int] | None = None
) -> str:
    """``generateRandomId()`` — see module docstring for the formula.

    ``rng`` stands in for ``SecureRandom.nextLong()``; it must return a Java
    long (the final value of the do-nothing loop is used).
    """

    clock = clock or (lambda: int(time.time() * 1000))
    rng = rng or (lambda: int.from_bytes(_secrets.token_bytes(8), "big", signed=True))
    millis_tail = str(clock())[-5:]
    model6 = model.replace(" ", "")
    while len(model6) < 6:
        model6 += "0"
    model6 = model6[:6]
    hex_tail = format(rng() & 0xFFFFFFFFFFFFFFFF, "x")[:4]  # Long.toHexString
    return millis_tail + model6 + hex_tail


def remote_device_id(
    brand: str,
    model: str,
    random_ids: tuple[str, str, str, str],
) -> str:
    """``getRemoteDeviceID`` — ``random_ids`` are the four persisted
    ``randomIdN`` strings (generate once, reuse)."""

    r1, r2, r3, r4 = random_ids
    return _md5_lower(brand + model)[4:16] + _md5_lower(r3 + r4)[8:24] + _md5_lower(r1 + r2)[16:]


class PhoneUtil:
    """Static-state port of ``PhoneUtil`` — ``mDeviceId``/``randomIdN``
    caches plus the ``SecuredPreferenceStore``-backed persistence."""

    RANDOM_ID_KEYS = ("randomId1", "randomId2", "randomId3", "randomId4")

    def __init__(
        self,
        store: MutableMapping[str, str],
        brand: str = "",
        model: str = "",
        clock: Callable[[], int] | None = None,
        rng: Callable[[], int] | None = None,
    ) -> None:
        self._store = store
        self._brand = brand
        self._model = model
        self._clock = clock
        self._rng = rng
        self._device_id: str | None = None
        self._random_ids: dict[str, str] = {}

    def _random_id(self, key: str) -> str:
        """``getRandomIdN``: memory cache → preference → generate+persist."""

        if key in self._random_ids:
            return self._random_ids[key]
        persisted = self._store.get(key, "")
        if len(persisted) != 0:
            self._random_ids[key] = persisted
            return persisted
        value = generate_random_id(self._model, self._clock, self._rng)
        self._store[key] = value
        self._random_ids[key] = value
        return value

    def get_device_id(self) -> str:
        """``getDeviceID``: static cache → persisted ``deviceId`` →
        ``getRemoteDeviceID`` (persisted)."""

        if not self._device_id:
            persisted = self._store.get("deviceId", "")
            if persisted:
                self._device_id = persisted
            else:
                self._device_id = remote_device_id(
                    self._brand,
                    self._model,
                    tuple(self._random_id(k) for k in self.RANDOM_ID_KEYS),  # type: ignore[arg-type]
                )
                self._store["deviceId"] = self._device_id
        return self._device_id
