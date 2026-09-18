"""Config flow for Popur."""

from __future__ import annotations

import logging
import uuid
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.helpers import config_validation as cv

from pypopur.mobile import (
    MobileAppProfile,
    MobileAuthenticationError,
    PopurAccount,
    ThingMobileApi,
)

from .const import CONF_INSTALL_ID, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Optional(CONF_INSTALL_ID): cv.string,
        vol.Optional(
            CONF_SCAN_INTERVAL,
            default=int(DEFAULT_SCAN_INTERVAL.total_seconds()),
        ): vol.All(cv.positive_int, vol.Range(min=15)),
    }
)


class PopurConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a Popur config flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            email = user_input[CONF_EMAIL].strip()
            password = user_input[CONF_PASSWORD]
            install_id = user_input.get(CONF_INSTALL_ID) or uuid.uuid4().hex

            api = ThingMobileApi(
                MobileAppProfile.bundled_popur_app2(), install_id=install_id
            )
            account = PopurAccount(api)
            try:
                session = await account.login(email, password)
            except MobileAuthenticationError:
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Popur login failed")
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(session.uid or email)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=email,
                    data={
                        CONF_EMAIL: email,
                        CONF_PASSWORD: password,
                        CONF_INSTALL_ID: install_id,
                        CONF_SCAN_INTERVAL: user_input[CONF_SCAN_INTERVAL],
                    },
                )

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )
