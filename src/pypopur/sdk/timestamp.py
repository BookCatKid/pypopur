"""Port of ``com.thingclips.smart.android.network.util.TimeStampManager``.

smali: smali_classes3/.../network/util/TimeStampManager.smali

``getCurrentTimeStamp()`` returns unix SECONDS computed as::

    (elapsedRealtime() - baseTimeElapsed) / 1000 + baseServerTimeStamp

where the base is anchored when the manager starts (or when a server
timestamp update arrives), so the value tracks server time but advances on
the monotonic clock. ``getCurrentTimeStampMillis()`` is the millisecond twin.
A negative elapsed delta (clock anomaly) rebases to wall clock.
"""

from __future__ import annotations

import threading
import time


def _elapsed_ms() -> int:
    """``SystemClock.elapsedRealtime()`` — monotonic ms since boot."""

    return int(time.monotonic() * 1000)


def _wall_ms() -> int:
    return int(time.time() * 1000)


class TimeStampManager:
    """Singleton in Java (``SingletonHolder``); instantiable here for tests."""

    _instance: TimeStampManager | None = None
    _instance_lock = threading.Lock()

    def __init__(
        self,
        monotonic_ms=_elapsed_ms,
        wall_ms=_wall_ms,
        store=None,
    ) -> None:
        self._monotonic_ms = monotonic_ms
        self._wall_ms = wall_ms
        # Java ctor: timeFlag=-1, baseTimeElapsed=elapsedRealtime(),
        # baseServerTimeStamp=currentTimeMillis()/1000.
        self._time_flag = -1
        self._base_elapsed = self._monotonic_ms()
        self._base_server = self._wall_ms() // 1000
        self._store = store  # optional dict-like for "timestamp_difference" prefs

    @classmethod
    def instance(cls) -> TimeStampManager:
        if cls._instance is None:
            with cls._instance_lock:
                cls._instance = TimeStampManager()
        return cls._instance

    def _restore(self) -> None:
        """``restore(Context)``: reload persisted bases from the
        "timestamp_difference" SharedPreferences when both are > 0."""

        if self._store is None:
            return  # flag stays -1 — Java re-runs restore() on every call
        base_elapsed = self._store.get("base_time_elapsed", -1)
        base_server = self._store.get("base_server_timestamp", -1)
        if base_elapsed > 0 and base_server > 0:
            self._base_elapsed = base_elapsed
            self._base_server = base_server
            self._time_flag = 1  # TIME_FLAG_LOADED

    def update_timestamp(self, server_timestamp: int) -> None:
        """Record a server-provided unix-second timestamp as the new base."""

        if server_timestamp <= 0:
            return
        self._base_elapsed = self._monotonic_ms()
        self._base_server = server_timestamp
        self._time_flag = 1
        if self._store is not None:
            self._store["base_time_elapsed"] = self._base_elapsed
            self._store["base_server_timestamp"] = self._base_server

    def get_current_timestamp(self) -> int:
        """``getCurrentTimeStamp()`` — unix seconds."""

        if self._time_flag == -1:
            self._restore()
        delta = self._monotonic_ms() - self._base_elapsed
        if delta < 0:
            self._base_elapsed = self._monotonic_ms()
            self._base_server = self._wall_ms() // 1000
            return self._base_server
        return delta // 1000 + self._base_server

    def get_current_timestamp_millis(self) -> int:
        """``getCurrentTimeStampMillis()`` — ``baseServer*1000 + elapsedDelta``."""

        if self._time_flag == -1:
            self._restore()
        delta = self._monotonic_ms() - self._base_elapsed
        if delta < 0:
            self._base_elapsed = self._monotonic_ms()
            self._base_server = self._wall_ms() // 1000
            return self._wall_ms()
        return self._base_server * 1000 + delta
