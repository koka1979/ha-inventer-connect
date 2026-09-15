"""Polling coordinator for an inVENTer Connect controller."""

from __future__ import annotations

import logging
from collections.abc import Coroutine
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import InventerAuthError, InventerClient, InventerError
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN
from .protocol import ZoneStatus

_LOGGER = logging.getLogger(__name__)


class InventerCoordinator(DataUpdateCoordinator[ZoneStatus]):
    """Reads one zone's status on an interval.

    The BLE channel needs several round trips per read, so every entity shares
    this one poll rather than fetching for itself.
    """

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry,
                 client: InventerClient, zone: int) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} zone {zone}",
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
        )
        self.client = client
        self.zone = zone
        self.entry = entry

    async def _async_update_data(self) -> ZoneStatus:
        try:
            return await self.client.async_read_zone(self.zone)
        except InventerAuthError as err:
            # Retrying will not fix a wrong PIN, so send the user to reconfigure.
            raise ConfigEntryAuthFailed(str(err)) from err
        except InventerError as err:
            raise UpdateFailed(str(err)) from err

    async def async_command(self, command: Coroutine[Any, Any, None]) -> None:
        """Run a write command, then refresh so the UI reflects the result."""
        try:
            await command
        except InventerError as err:
            raise HomeAssistantError(f"inVENTer command failed: {err}") from err
        await self.async_request_refresh()
