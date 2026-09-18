"""Ports of ``SandO`` and ``SandRMap`` — the per-device s/o sequence state.

smali:
- smali_classes3/com/thingclips/smart/interior/device/confusebean/SandO.smali
- smali_classes3/com/thingclips/smart/android/device/utils/SandRMap.smali

``s`` starts at 2 and is bumped by ``SAdd()`` per request; ``o`` is fixed at
construction to ``(int)(Math.random() * 1_000_000) + 1000`` — inclusive range
[1000, 1000999].
"""

from __future__ import annotations

import random
import threading

_R_MIN = 1000
_R_MAX = 1_000_000


class SandO:
    """``com.thingclips.smart.interior.device.confusebean.SandO``."""

    def __init__(self) -> None:
        self.s: int = 2  # volatile int
        # (int)(Math.random()*1e6) truncates → 0..999999 → +1000
        self.o: int = int(random.random() * _R_MAX) + _R_MIN

    def s_add(self) -> None:
        """``SAdd()`` — Java ``s++`` on a volatile field (non-atomic)."""

        self.s += 1

    def get_o(self) -> int:
        return self.o

    def get_s(self) -> int:
        return self.s

    def set_s(self, value: int) -> None:
        self.s = value


class SandRMap:
    """``com.thingclips.smart.android.device.utils.SandRMap`` — process-wide
    singleton ``HashMap<devId, SandO>`` with double-checked locking."""

    _instance: SandRMap | None = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._map: dict[str, SandO] = {}

    @classmethod
    def get_instance(cls) -> SandRMap:
        if cls._instance is None:
            with cls._instance_lock:
                cls._instance = SandRMap()
        return cls._instance

    def get(self, dev_id: str) -> SandO | None:
        return self._map.get(dev_id)

    def put(self, dev_id: str, sand_o: SandO) -> None:
        self._map[dev_id] = sand_o

    def on_destroy(self) -> None:
        """``onDestroy()`` — clears the map and resets the singleton."""

        self._map.clear()
        SandRMap._instance = None
