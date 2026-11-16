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
