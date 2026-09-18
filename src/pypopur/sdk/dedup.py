"""Port of ``com.thingclips.sdk.device.qdddqdp`` — "ThingMessageCache", the
message dedup store used by LAN/MQTT inbound dispatch.

smali: smali_classes3/com/thingclips/sdk/device/qdddqdp.smali

Two synchronized ``HashMap<String,Long>`` stores keyed by string concat,
value ``System.currentTimeMillis()``:

- ``isDataUpdated(devId, s)`` — key ``devId+s``; ``s == -1`` → dedup stage
  passes immediately. Hit within 5000 ms → key REMOVED, dedup passes.
  Miss → evict-all-stale when size > 300, store, dedup fails. The public
  result ANDs the dedup outcome with ``!isLowPower(device)``.
- ``isDataUpdated(devId, s, o)`` — ``o == 0`` → dedup fails immediately (no
  store). Key ``devId+s+o``; eviction threshold size > 900.

Net effect: a (devId, s[, o]) tuple is accepted once; a repeat inside the
window is swallowed ("data is updated") unless the device is low-power
(``attribute & 0x1000``), whose repeats always pass.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

WINDOW_MS = 5000  # 0x1388
_S_THRESHOLD = 300  # 0x12c — 2-arg store evicts when size exceeds this
_SO_THRESHOLD = 900  # 0x384 — 3-arg store

# DeviceBean attribute bit marking low-power devices (getAttribute() & 0x1000).
LOW_POWER_ATTRIBUTE = 0x1000


def _millis() -> int:
    return int(time.time() * 1000)


class ThingMessageCache:
    """``qdddqdp`` — instantiated per-process as a singleton in Java; here it
    is a plain class so tests can isolate state.

    ``attribute_provider`` stands in for
    ``bpbqqdq.bdpdqbp().getDev(devId).getAttribute()``: return the device's
    attribute int, or ``None`` when the device is unknown (Java: null bean →
    treated as "updated").
    """

    def __init__(
        self,
        attribute_provider: Callable[[str], int | None] | None = None,
        clock: Callable[[], int] = _millis,
    ) -> None:
        self._s_store: dict[str, int] = {}
        self._so_store: dict[str, int] = {}
        self._lock = threading.RLock()
        self._attribute_provider = attribute_provider
        self._clock = clock

    def _not_low_power(self, dev_id: str) -> bool:
        """``bdpdqbp(String)``: null device → true; else ``!(attr & 0x1000)``."""

        if self._attribute_provider is None:
            return True
        attribute = self._attribute_provider(dev_id)
        if attribute is None:
            return True
        return (attribute & LOW_POWER_ATTRIBUTE) <= 0

    def _lookup(self, store: dict[str, int], key: str, threshold: int, now: int) -> bool:
        """``pdqppqb`` core: hit-in-window → remove, true; miss → evict stale
        past threshold, store, false."""

        seen = store.get(key)
        if seen is not None and abs(now - seen) < WINDOW_MS:
            del store[key]
            return True
        if len(store) > threshold:
            for stale_key in [
                k for k, ts in store.items() if ts is None or abs(now - ts) >= WINDOW_MS
            ]:
                del store[stale_key]
        store[key] = now
        return False

    def _check_s(self, dev_id: str, s: int, now: int) -> bool:
        """``pdqppqb(String, I)`` — the raw dedup stage."""

        if s == -1:
            return True
        return self._lookup(self._s_store, f"{dev_id}{s}", _S_THRESHOLD, now)

    def _check_so(self, dev_id: str, s: int, o: int, now: int) -> bool:
        """``pdqppqb(String, II)`` — ``o == 0`` never dedups."""

        if o == 0:
            return False
        return self._lookup(self._so_store, f"{dev_id}{s}{o}", _SO_THRESHOLD, now)

    def is_data_updated(self, dev_id: str, s: int) -> bool:
        """``bdpdqbp(String, I)`` — synchronized."""

        with self._lock:
            if self._check_s(dev_id, s, self._clock()):
                return self._not_low_power(dev_id)
            return False

    def is_data_updated_so(self, dev_id: str, s: int, o: int) -> bool:
        """``bdpdqbp(String, II)`` — synchronized."""

        with self._lock:
            if self._check_so(dev_id, s, o, self._clock()):
                return self._not_low_power(dev_id)
            return False
