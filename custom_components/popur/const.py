"""Constants for the Popur integration."""

from datetime import timedelta
from typing import Final

DOMAIN: Final = "popur"

CONF_INSTALL_ID: Final = "install_id"
CONF_SCAN_INTERVAL: Final = "scan_interval"
CONF_HOST: Final = "host"

DEFAULT_SCAN_INTERVAL: Final = timedelta(seconds=60)
MIN_SCAN_INTERVAL: Final = timedelta(seconds=15)

# Cloud-side data (settings-DP shadow, pets, usage records) refreshes on a
# slower cadence — the LAN channel covers live device state between these.
CLOUD_REFRESH_INTERVAL: Final = timedelta(minutes=10)

PET_RECORDS_PAGE_SIZE: Final = 25

# Dispatcher signals for the event platform. Activity/fault events are sent
# per device with ``(ActivityEvent, attributes)``; pet visits per pet with
# ``(attributes,)``.
EVENT_TYPE_VISIT_RECORDED: Final = "visit_recorded"


def signal_device_event(dev_id: str) -> str:
    """Dispatcher signal carrying live MQTT activity/fault events for one device."""

    return f"{DOMAIN}_event_{dev_id}"


def signal_pet_visit(pet_id: int) -> str:
    """Dispatcher signal carrying newly recorded visits for one pet."""

    return f"{DOMAIN}_pet_visit_{pet_id}"
