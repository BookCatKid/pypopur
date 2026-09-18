"""App-layer ports of ``com.popur.android`` classes (DP state, control helpers)."""

from .dp101 import (
    BIN_STATUS_VALUES,
    CAT_PRESENCE_VALUES,
    COMPLETED_RUNNING_STATUSES,
    DEFAULT_REPORT,
    LEGACY_NORMALIZED_KEYS,
    MACHINE_STATUS_VALUES,
    PENDING_CLEANING_ACTIONS,
    RUNNING_STATUS_VALUES,
    ParsedReport,
    apply_to_map,
    bin_status_from_dp_states,
    cat_presence_from_dp_states,
    clean_control_from_dp_states,
    countdown_minutes_from_dp_states,
    decode_to_bytes,
    device_color_code_from_label,
    device_color_label_from_code,
    encode_report,
    fault_from_dp_states,
    machine_status_from_dp_states,
    merge_during_pending_cleaning_action,
    migrate_legacy_keys,
    normalized_copy,
    parse_device_color_code,
    parse_fault_value,
    parse_from_dp_states,
    parse_report,
    parse_smooth_spread_count,
    patch_dp_states,
    running_status_from_dp_states,
    spread_count_from_dp_states,
    strip_legacy_keys,
    validate_active_shield_range,
    validate_active_shield_sensitive,
    validate_delay_minutes,
    validate_smooth_spread,
    validate_timezone_offset,
)
from .dp_string import (
    dp_flag_arg,
    dp_string_arg,
    parse_dp_string,
    serialize_dps,
)
from .helper import DeviceCommandError, UnifiedDeviceControlHelper
from .manager import (
    BATCH_QUERY_EXCEPTION,
    COMMAND_EXCEPTION,
    DEVICE_NOT_FOUND,
    NO_CONTROL_METHOD,
    SDK_ERROR,
    DeviceListenerBridge,
    DeviceState,
    UnifiedDeviceControlManager,
    read_device_dps,
)
from .repository import (
    CRITICAL_DP_ORDER,
    EMPTY_CLEANING_PROGRESS,
    CleaningProgressMetadata,
    DeviceRepository,
    RepositoryDevice,
    cleaning_progress_from_json,
    cleaning_progress_to_json,
)
from .resolver import (
    CRITICAL_DP_KEYS,
    DeviceBinStatus,
    DeviceStatus,
    derive_status,
    merge_fill_missing,
    merge_with_timestamps,
)

__all__ = [name for name in dir() if not name.startswith("_")]
