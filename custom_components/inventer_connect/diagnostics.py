"""Diagnostics for inVENTer Connect.

Includes the raw zone-row packet. Several fields in that row are still
unmapped, so a real capture is what lets the layout be finished.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from homeassistant.core import HomeAssistant

from . import InventerConfigEntry
from .client import InventerError
from .const import CONF_ADDRESS_KEY, CONF_PIN
from .protocol import TYPE_ZONE_VIEW_ROW, request_zone_row

TO_REDACT = {CONF_PIN, CONF_ADDRESS_KEY}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: InventerConfigEntry
) -> dict[str, Any]:
    coordinator = entry.runtime_data

    diagnostics: dict[str, Any] = {
        "entry": {k: v for k, v in entry.data.items() if k not in TO_REDACT},
        "options": dict(entry.options),
        "zone": coordinator.zone,
        "status": asdict(coordinator.data) if coordinator.data else None,
    }

    try:
        raw = await coordinator.client.async_request(
            request_zone_row(coordinator.zone), TYPE_ZONE_VIEW_ROW)
    except InventerError as err:
        diagnostics["raw_zone_row_error"] = str(err)
    else:
        diagnostics["raw_zone_row"] = raw.hex()
        diagnostics["raw_zone_row_length"] = len(raw)

    try:
        diagnostics["device_info"] = await coordinator.client.async_device_info()
    except InventerError as err:
        diagnostics["device_info_error"] = str(err)

    return diagnostics
