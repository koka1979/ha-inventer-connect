"""Config flow for inVENTer Connect."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_ble_device_from_address,
    async_discovered_service_info,
)
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import callback
from homeassistant.helpers import config_validation as cv

from .client import InventerAuthError, InventerError, async_probe
from .const import (
    CONF_KEEP_CONNECTED,
    CONF_PIN,
    CONF_ZONE,
    CONNECTION_SERVICE,
    DEFAULT_ZONE,
    DOMAIN,
    TRANSPORT_CHARACTERISTIC,
)

_LOGGER = logging.getLogger(__name__)

PIN_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PIN): cv.positive_int,
        vol.Optional(CONF_ZONE, default=DEFAULT_ZONE): vol.All(int, vol.Range(min=0, max=15)),
    }
)

REAUTH_SCHEMA = vol.Schema({vol.Required(CONF_PIN): cv.positive_int})


class InventerConfigFlow(ConfigFlow, domain=DOMAIN):
    """Pick a controller, then verify the PIN printed in its manual."""

    VERSION = 1

    def __init__(self) -> None:
        self._address: str | None = None
        self._name: str | None = None

    # --- discovery and selection -------------------------------------------

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        """Handle a controller found by the Bluetooth integration."""
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()

        self._address = discovery_info.address
        self._name = discovery_info.name or discovery_info.address
        self.context["title_placeholders"] = {"name": self._name}
        return await self.async_step_pin()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Let the user choose among nearby controllers."""
        if user_input is not None:
            self._address = user_input[CONF_ADDRESS]
            await self.async_set_unique_id(self._address, raise_on_progress=False)
            self._abort_if_unique_id_configured()
            return await self.async_step_pin()

        candidates = {
            info.address: f"{info.name or 'inVENTer'} ({info.address})"
            for info in async_discovered_service_info(self.hass, connectable=True)
            if self._looks_like_controller(info)
        }
        for entry in self._async_current_entries():
            candidates.pop(entry.data.get(CONF_ADDRESS), None)

        if not candidates:
            return self.async_abort(reason="no_devices_found")

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({vol.Required(CONF_ADDRESS): vol.In(candidates)}),
        )

    # --- PIN verification ---------------------------------------------------

    async def _async_verify_pin(self, pin: int) -> tuple[dict[str, str], dict[str, str]]:
        """Connect once to check the PIN. Returns (errors, device info)."""
        assert self._address is not None
        device = async_ble_device_from_address(self.hass, self._address, connectable=True)

        if device is None:
            return {"base": "cannot_connect"}, {}

        try:
            info = await async_probe(device, pin)
        except InventerAuthError:
            return {CONF_PIN: "invalid_pin"}, {}
        except InventerError as err:
            _LOGGER.debug("Probe of %s failed: %s", self._address, err)
            return {"base": "cannot_connect"}, {}

        return {}, info

    async def async_step_pin(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Verify the PIN, then create the entry."""
        errors: dict[str, str] = {}

        if user_input is not None:
            errors, info = await self._async_verify_pin(user_input[CONF_PIN])
            if not errors:
                return self.async_create_entry(
                    title=info.get("model") or self._name or "inVENTer Connect",
                    data={
                        CONF_ADDRESS: self._address,
                        CONF_PIN: user_input[CONF_PIN],
                        CONF_ZONE: user_input.get(CONF_ZONE, DEFAULT_ZONE),
                    },
                )

        return self.async_show_form(
            step_id="pin",
            data_schema=PIN_SCHEMA,
            errors=errors,
            description_placeholders={"name": self._name or ""},
        )

    # --- reauth -------------------------------------------------------------

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """Start over when the controller stops accepting the stored PIN."""
        self._address = entry_data[CONF_ADDRESS]
        self._name = self._get_reauth_entry().title
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the PIN again and update the existing entry in place."""
        errors: dict[str, str] = {}

        if user_input is not None:
            errors, _info = await self._async_verify_pin(user_input[CONF_PIN])
            if not errors:
                return self.async_update_reload_and_abort(
                    self._get_reauth_entry(),
                    data_updates={CONF_PIN: user_input[CONF_PIN]},
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=REAUTH_SCHEMA,
            errors=errors,
            description_placeholders={"name": self._name or ""},
        )

    # --- helpers ------------------------------------------------------------

    @staticmethod
    def _looks_like_controller(info: BluetoothServiceInfoBleak) -> bool:
        """Match on the advertised connection service.

        Advertised names vary by model, so the service UUID is the more
        reliable signal. The PIN step confirms compatibility for real by
        checking for the transport characteristic once connected.
        """
        uuids = {uuid.lower() for uuid in info.service_uuids}
        return bool(uuids & {TRANSPORT_CHARACTERISTIC, CONNECTION_SERVICE})

    @staticmethod
    @callback
    def async_get_options_flow(entry: ConfigEntry) -> OptionsFlow:
        return InventerOptionsFlow()


class InventerOptionsFlow(OptionsFlow):
    """Expose the one setting worth changing after setup."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)

        current = self.config_entry.options.get(CONF_KEEP_CONNECTED, False)
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {vol.Optional(CONF_KEEP_CONNECTED, default=current): bool}
            ),
        )
