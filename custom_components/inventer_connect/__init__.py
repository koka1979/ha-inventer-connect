"""The inVENTer Connect integration."""

from __future__ import annotations

import logging

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .client import InventerClient
from .const import CONF_KEEP_CONNECTED, CONF_PIN, CONF_ZONE, DEFAULT_ZONE
from .coordinator import InventerCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.FAN, Platform.SENSOR]

#: entry.runtime_data holds the InventerCoordinator. Spelled without the 3.12
#: ``type`` alias so the integration also imports on older Home Assistant cores.
InventerConfigEntry = ConfigEntry


async def async_setup_entry(hass: HomeAssistant, entry: InventerConfigEntry) -> bool:
    """Set up a controller from a config entry."""
    address: str = entry.data[CONF_ADDRESS]

    def lookup_device():
        """Resolve the address afresh each time.

        The device may move between the local adapter and a proxy, so the
        client must not hold on to a stale BLEDevice.
        """
        return bluetooth.async_ble_device_from_address(hass, address, connectable=True)

    if lookup_device() is None:
        raise ConfigEntryNotReady(
            f"inVENTer controller {address} is not currently reachable over Bluetooth")

    client = InventerClient(
        lookup_device,
        entry.data[CONF_PIN],
        keep_connected=entry.options.get(CONF_KEEP_CONNECTED, False),
    )
    coordinator = InventerCoordinator(
        hass, entry, client, entry.data.get(CONF_ZONE, DEFAULT_ZONE))

    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = coordinator
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: InventerConfigEntry) -> bool:
    """Unload a config entry and drop the BLE link."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.client.disconnect()
    return unloaded


async def _async_update_listener(hass: HomeAssistant, entry: InventerConfigEntry) -> None:
    """Reload when options change, so the new settings take effect."""
    await hass.config_entries.async_reload(entry.entry_id)
