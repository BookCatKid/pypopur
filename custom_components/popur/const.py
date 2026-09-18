"""Constants for the Popur integration."""

from datetime import timedelta
from typing import Final

DOMAIN: Final = "popur"

CONF_INSTALL_ID: Final = "install_id"
CONF_SCAN_INTERVAL: Final = "scan_interval"

DEFAULT_SCAN_INTERVAL: Final = timedelta(seconds=60)
MIN_SCAN_INTERVAL: Final = timedelta(seconds=15)

PET_RECORDS_PAGE_SIZE: Final = 25
