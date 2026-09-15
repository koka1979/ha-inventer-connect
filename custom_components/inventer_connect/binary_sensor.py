"""Binary sensors for an inVENTer Connect zone."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import InventerConfigEntry
from .entity import InventerEntity
from .protocol import ZoneStatus


@dataclass(frozen=True, kw_only=True)
class InventerBinarySensorDescription(BinarySensorEntityDescription):
    """Adds the accessor that pulls the flag out of a zone status."""

    value_fn: Callable[[ZoneStatus], bool]


BINARY_SENSORS: tuple[InventerBinarySensorDescription, ...] = (
    InventerBinarySensorDescription(
        key="boost_active",
        translation_key="boost_active",
        value_fn=lambda status: status.boosting,
    ),
    InventerBinarySensorDescription(
        key="pause_active",
        translation_key="pause_active",
        value_fn=lambda status: status.paused,
    ),
    InventerBinarySensorDescription(
        key="timer_active",
        translation_key="timer_active",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda status: status.timer_active,
    ),
    InventerBinarySensorDescription(
        key="global_command",
        translation_key="global_command",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda status: status.global_command,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: InventerConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities(
        InventerBinarySensor(coordinator, description) for description in BINARY_SENSORS
    )


class InventerBinarySensor(InventerEntity, BinarySensorEntity):
    """One boolean flag from a zone."""

    entity_description: InventerBinarySensorDescription

    def __init__(self, coordinator, description: InventerBinarySensorDescription) -> None:
        super().__init__(coordinator, description.key)
        self.entity_description = description

    @property
    def is_on(self) -> bool | None:
        status = self.zone_status
        return None if status is None else self.entity_description.value_fn(status)
