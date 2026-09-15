"""Fan entity for an inVENTer Connect zone."""

from __future__ import annotations

import math
from typing import Any

from homeassistant.components.fan import FanEntity, FanEntityFeature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util.percentage import (
    percentage_to_ranged_value,
    ranged_value_to_percentage,
)

from . import InventerConfigEntry
from .const import DEFAULT_SCAN_INTERVAL
from .entity import InventerEntity
from .protocol import MAX_FAN_SPEED, PLAY_MODE_BOOST, PLAY_MODE_PAUSE

SPEED_RANGE = (1, MAX_FAN_SPEED)

PRESET_BOOST = "boost"
PRESET_PAUSE = "pause"
PRESET_AUTO = "auto"

#: Overrides carry a timeout; without one the controller would hold the speed
#: indefinitely. Two polls' worth keeps the zone under our control between
#: refreshes while still falling back on its own if Home Assistant goes away.
OVERRIDE_TIMEOUT = DEFAULT_SCAN_INTERVAL * 2

#: The app fixes mode 1 alongside a manual speed.
MANUAL_FAN_MODE = 1


async def async_setup_entry(
    hass: HomeAssistant,
    entry: InventerConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    async_add_entities([InventerFan(entry.runtime_data)])


class InventerFan(InventerEntity, FanEntity):
    """One ventilation zone as a fan."""

    _attr_name = None
    _attr_translation_key = "ventilation"
    _attr_supported_features = (
        FanEntityFeature.SET_SPEED
        | FanEntityFeature.PRESET_MODE
        | FanEntityFeature.TURN_ON
        | FanEntityFeature.TURN_OFF
    )
    _attr_preset_modes = [PRESET_AUTO, PRESET_BOOST, PRESET_PAUSE]

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "fan")

    @property
    def is_on(self) -> bool | None:
        status = self.zone_status
        return None if status is None else status.is_on

    @property
    def percentage(self) -> int | None:
        status = self.zone_status
        if status is None:
            return None
        if status.paused or status.fan_speed == 0:
            return 0
        return ranged_value_to_percentage(SPEED_RANGE, status.fan_speed)

    @property
    def speed_count(self) -> int:
        return MAX_FAN_SPEED

    @property
    def preset_mode(self) -> str | None:
        status = self.zone_status
        if status is None:
            return None
        if status.play_mode == PLAY_MODE_BOOST:
            return PRESET_BOOST
        if status.play_mode == PLAY_MODE_PAUSE:
            return PRESET_PAUSE
        return PRESET_AUTO

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        status = self.zone_status
        if status is None:
            return {}
        return {
            "zone": self.coordinator.zone,
            "fan_speed": status.fan_speed,
            "ventilation_mode": status.ventilation_mode,
            "ventilation_profile": status.ventilation_profile,
            "timer_remaining": status.timer if status.timer_active else 0,
            "global_command_active": status.global_command,
        }

    async def async_set_percentage(self, percentage: int) -> None:
        if percentage == 0:
            await self.async_turn_off()
            return

        speed = math.ceil(percentage_to_ranged_value(SPEED_RANGE, percentage))
        speed = max(1, min(MAX_FAN_SPEED, speed))
        await self.coordinator.async_command(
            self.coordinator.client.async_set_speed(
                self.coordinator.zone, speed, MANUAL_FAN_MODE, OVERRIDE_TIMEOUT)
        )

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        client = self.coordinator.client
        zone = self.coordinator.zone

        if preset_mode == PRESET_BOOST:
            command = client.async_boost(zone)
        elif preset_mode == PRESET_PAUSE:
            command = client.async_pause(zone)
        else:
            # Auto means: drop the override and let the zone's own profile run.
            command = client.async_cancel(zone)

        await self.coordinator.async_command(command)

    async def async_turn_on(
        self,
        percentage: int | None = None,
        preset_mode: str | None = None,
        **kwargs: Any,
    ) -> None:
        if preset_mode is not None:
            await self.async_set_preset_mode(preset_mode)
            return
        if percentage is not None and percentage > 0:
            await self.async_set_percentage(percentage)
            return
        # Plain turn_on: hand the zone back to its programmed profile.
        await self.async_set_preset_mode(PRESET_AUTO)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.async_set_preset_mode(PRESET_PAUSE)
