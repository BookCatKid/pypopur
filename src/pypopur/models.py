"""Immutable public models for Popur firmware 4.x."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag, StrEnum
from types import MappingProxyType
from typing import Any


class BinStatus(StrEnum):
    """DP101 bin-state values in APK order.

    ``BIN_OPENED`` keeps the firmware/app spelling on the wire.
    """

    UNFOUND = "unfound"
    NEAR_EMPTY = "near_empty"
    HALF_EMPTY = "half_empty"
    ALMOST_FULL = "almost_full"
    BIN_FULL = "bin_full"
    BIN_OPENED = "bin_opned"


class RunningStatus(StrEnum):
    IDLE = "idle"
    CLEAN_START = "clean_start"
    CLEAN_PAUSE = "clean_pause"
    MANUAL_CLEAN_COMPLETED = "manual_clean_completed"
    SCHEDULED_CLEAN_COMPLETED = "scheduled_clean_completed"
    # The doubled "t" is present in the official app and is preserved as a wire value.
    AUTOMATIC_CLEAN_COMPLETED = "auttomatic_clean_completed"


class MachineStatus(StrEnum):
    POWER_ON = "power_on"
    HIBERNATING = "hibernating"
    DISTURB_MODE = "disturb_mode"
    POWER_OFF = "power_off"


class MachineControl(StrEnum):
    """Commands accepted by the app's current DP109 power control."""

    POWER_ON = "power_on"
    POWER_OFF = "power_off"
    REBOOT = "reboot"


class SifterControl(StrEnum):
    """Commands accepted by the app's current DP108 sifter control."""

    CLOSE = "close"
    OPEN = "open"
    START_SCOOP = "start_scoop"
    PAUSE_SCOOP = "pause_scoop"


class SpecialOperation(StrEnum):
    """DP107 service commands, preserving firmware spelling."""

    ZERO_BIN = "zeoring"
    RECALIBRATE_SPIN_SENSOR = "specail_calibrate"


class CatPresence(StrEnum):
    NO_CAT = "no_cat"
    CAT_EXIST = "cat_exist"
    CAT_LEFT = "cat_left"
    CAT_DONE_BUSINESS = "cat_done_business"


@dataclass(frozen=True, slots=True)
class RunModeReport:
    bin_status: BinStatus = BinStatus.NEAR_EMPTY
    running_status: RunningStatus = RunningStatus.IDLE
    machine_status: MachineStatus = MachineStatus.POWER_ON
    cat_presence: CatPresence = CatPresence.NO_CAT
    countdown_minutes: int = 0


@dataclass(frozen=True, slots=True)
class ActiveShieldSettings:
    anti_interference: bool = False
    sensitivity: int = 5
    range: int = 3


@dataclass(frozen=True, slots=True)
class WeightFunctionSettings:
    automatic: bool = False
    sentinel: bool = False
    caring: bool = False
    track_pet_data: bool = True


@dataclass(frozen=True, slots=True)
class DetailedNotificationSettings:
    self_check_enabled: bool = False
    bin_full_enabled: bool = False
    manual_cleaning_enabled: bool = False
    scheduled_cleaning_enabled: bool = False
    automatic_cleaning_enabled: bool = False
    cleaning_started_enabled: bool = False
    pet_finished_enabled: bool = False
    pet_detected_enabled: bool = False


@dataclass(frozen=True, slots=True)
class DetailedNotificationExtSettings:
    new_firmware_enabled: bool = False
    pet_left_without_business_enabled: bool = False
    cleaning_paused_enabled: bool = False
    cleaning_resumed_enabled: bool = False


@dataclass(frozen=True, slots=True)
class PanelToggles:
    status_light_enabled: bool = True
    buzzer_enabled: bool = True
    pro_commands_enabled: bool = False


@dataclass(frozen=True, slots=True)
class SpinSettings:
    auto_power_cycle: bool = False
    lower_speed: bool = False
    reshuffle_enabled: bool = False
    reshuffle_oscillation: str = "2X"
    auto_self_check: bool = True


@dataclass(frozen=True, slots=True)
class SystemSettings:
    """Known fields in DP102 plus the original 29-byte payload.

    ``raw`` lets encoders preserve bytes that the APK does not currently expose.
    """

    active_shield: ActiveShieldSettings = field(default_factory=ActiveShieldSettings)
    delay_minutes: int = 5
    smooth_spread_count: int = 3
    timezone_offset_hours: int = 0
    device_color: str = "white"
    detailed_notifications: DetailedNotificationSettings = field(
        default_factory=DetailedNotificationSettings
    )
    notification_master_enabled: bool = False
    panel: PanelToggles = field(default_factory=PanelToggles)
    weight_functions: WeightFunctionSettings = field(default_factory=WeightFunctionSettings)
    spin: SpinSettings = field(default_factory=SpinSettings)
    detailed_notifications_ext: DetailedNotificationExtSettings = field(
        default_factory=DetailedNotificationExtSettings
    )
    raw: bytes = bytes(29)


@dataclass(frozen=True, slots=True)
class TimerSlice:
    enabled: bool = False
    repeat_mask: int = 0
    hour: int = 0
    minute: int = 0

    @property
    def has_schedule_data(self) -> bool:
        return bool(self.hour or self.minute or self.repeat_mask)


@dataclass(frozen=True, slots=True)
class TimePowerSettings:
    power_on: TimerSlice = field(default_factory=TimerSlice)
    power_off: TimerSlice = field(default_factory=TimerSlice)
    hibernate_start: bool = False
    hibernate_duration_minutes: int = 0


class DustbinSwitch(IntFlag):
    BIN_FULL_DETECTION = 0x01
    ALLOW_OVERFILL = 0x02
    KEEP_UPRIGHT = 0x04
    DUMP_OVERRIDE = 0x08
    BLOCK_ON_FULL = 0x10


@dataclass(frozen=True, slots=True)
class DustbinToggles:
    bin_full_detection: bool = True
    allow_overfill: bool = False
    keep_upright: bool = True
    dump_override: bool = False
    block_on_full: bool = False


class CalibrationLevel(IntEnum):
    PRECISE = 0
    BALANCED = 1
    EXTENDED = 2
    MAXIMUM = 3

    @property
    def label(self) -> str:
        return ("Precise", "Balanced", "Extended", "Maximum")[self.value]

    @property
    def percent(self) -> int:
        return (25, 50, 75, 100)[self.value]


@dataclass(frozen=True, slots=True)
class DustbinSettings:
    toggles: DustbinToggles = field(default_factory=DustbinToggles)
    calibration: CalibrationLevel = CalibrationLevel.BALANCED
    cycle_count: int = 5
    raw: bytes = bytes((0x05, 0x01, 0x05))


@dataclass(frozen=True, slots=True)
class KeyGesture:
    enabled: bool
    function: int


@dataclass(frozen=True, slots=True)
class KeySettings:
    lock_mask: int = 0
    press: KeyGesture = field(default_factory=lambda: KeyGesture(True, 0))
    hold_3s: KeyGesture = field(default_factory=lambda: KeyGesture(True, 2))
    hold_7s: KeyGesture = field(default_factory=lambda: KeyGesture(True, 3))

    def is_key_locked(self, key_index: int) -> bool:
        return 0 <= key_index < 4 and bool(self.lock_mask & (1 << key_index))


@dataclass(frozen=True, slots=True)
class SelfCheckStatus:
    progress: int
    raw: bytes = bytes(5)


@dataclass(frozen=True, slots=True)
class FaultItem:
    mask: int
    label: str
    url: str


class RecentActivity(IntEnum):
    IDLE = 0
    CAT_EXIST = 1
    CAT_LEFT = 2
    CAT_DONE_BUSINESS = 3
    MANUAL_CLEAN_COMPLETED = 4
    SCHEDULED_CLEAN_COMPLETED = 5
    AUTOMATIC_CLEAN_COMPLETED = 6
    BIN_FULL = 7
    SELF_CHECK_COMPLETED = 8
    CLEANING_STARTED = 9
    CLEANING_PAUSED = 10
    CLEANING_RESUMED = 11

    @property
    def display_text(self) -> str | None:
        return {
            self.IDLE: None,
            self.CAT_EXIST: "Pet detected",
            self.CAT_LEFT: "Pet left without business",
            self.CAT_DONE_BUSINESS: "Pet finished the business",
            self.MANUAL_CLEAN_COMPLETED: "Manual cleaning completed",
            self.SCHEDULED_CLEAN_COMPLETED: "Scheduled cleaning completed",
            self.AUTOMATIC_CLEAN_COMPLETED: "Automatic cleaning completed",
            self.BIN_FULL: "Bin full",
            self.SELF_CHECK_COMPLETED: "Self-check completed",
            self.CLEANING_STARTED: "Cleaning started",
            self.CLEANING_PAUSED: "Cleaning paused",
            self.CLEANING_RESUMED: "Cleaning resumed",
        }[self]


@dataclass(frozen=True, slots=True)
class NotificationSettings:
    master_enabled: bool = False
    pet_detected_enabled: bool = False
    pet_finished_enabled: bool = False
    pet_left_without_business_enabled: bool = False
    cleaning_started_enabled: bool = False
    cleaning_paused_enabled: bool = False
    cleaning_resumed_enabled: bool = False
    automatic_cleaning_enabled: bool = False
    scheduled_cleaning_enabled: bool = False
    manual_cleaning_enabled: bool = False
    bin_full_enabled: bool = False
    self_check_enabled: bool = False


@dataclass(frozen=True, slots=True)
class DeviceSnapshot:
    """Decoded point-in-time device state returned by :meth:`PopurClient.refresh`."""

    raw_dps: Mapping[int, Any]
    run_mode: RunModeReport | None = None
    machine_status: MachineStatus | None = None
    cat_presence: CatPresence | None = None
    system_settings: SystemSettings | None = None
    time_power: TimePowerSettings | None = None
    dustbin: DustbinSettings | None = None
    key_settings: KeySettings | None = None
    self_check: SelfCheckStatus | None = None
    self_check_fault_value: int = 0
    self_check_faults: tuple[FaultItem, ...] = ()
    recent_activity: RecentActivity | None = None
    notifications: NotificationSettings = field(default_factory=NotificationSettings)
    cat_weight: int | float | None = None
    daily_clean_count: int | None = None
    clean_duration: int | None = None
    automatic_clean_count: int | None = None
    scheduled_clean_count: int | None = None
    manual_clean_count: int | None = None
    total_use_time: int | None = None
    clean_count_after_full: int | None = None
    fault_free_time: int | None = None
    total_clean_count: int | None = None
    cat_toilet_time: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw_dps", MappingProxyType(dict(self.raw_dps)))
        if self.machine_status is None and self.run_mode is not None:
            object.__setattr__(self, "machine_status", self.run_mode.machine_status)
        if self.cat_presence is None and self.run_mode is not None:
            object.__setattr__(self, "cat_presence", self.run_mode.cat_presence)
